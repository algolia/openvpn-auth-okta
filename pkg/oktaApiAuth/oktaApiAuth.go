package oktaApiAuth

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

func NewOktaApiAuth() *OktaApiAuth {
	/*
		utsname := unix.Utsname{}
		_ = unix.Uname(&utsname)
		userAgent := fmt.Sprintf("OktaOpenVPN/2.1.0 (%s %s) Go-http-client/%s",
			utsname.Sysname,
			utsname.Release,
			runtime.Version()[2:])
		fmt.Printf("agent: %s\n", userAgent)

		using dynamic user agent does not work ....
		so for now use a const var
	*/

	return &OktaApiAuth{
		ApiConfig: &OktaAPIConfig{
			AllowUntrustedUsers: false,
			MFARequired:         false,
			MFAPushMaxRetries:   20,
			MFAPushDelaySeconds: 3,
			AllowedGroups:       "",
		},
		UserConfig: &OktaUserConfig{},
		userAgent:  userAgent,
	}
}

func (auth *OktaApiAuth) verifyTOTPFactor(stateToken string, factorsTOTP []interface{}) (err error) {
	var res map[string]interface{}
	// If no passcode is provided, this is a noop
	for count, factor := range factorsTOTP {
		fid := factor.(map[string]interface{})["id"].(string)
		provider := factor.(map[string]interface{})["provider"].(string)
		res, err = auth.doAuth(fid, stateToken)
		if err != nil {
			if count == len(factorsTOTP)-1 {
				_, _ = auth.cancelAuth(stateToken)
				return err
			} else {
				continue
			}
		}
		if _, ok := res["status"]; ok {
			if res["status"] == "SUCCESS" {
				log.Infof("authenticated with %s TOTP MFA", provider)
				return nil
			}
		} else {
			// Reached only when "TOTP" MFA is used
			if _, ok := res["errorCauses"]; ok {
				cause := res["errorCauses"].([]interface{})[0]
				errorSummary := cause.(map[string]interface{})["errorSummary"].(string)
				log.Warningf("%s TOTP MFA authentication failed: %s",
					provider,
					errorSummary)
				// Multiple OTP providers can be configured
				// let's ensure we tried all before returning
				if count == len(factorsTOTP)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return errors.New("TOTP MFA failed")
				}
			}
		}
	}
	return errors.New("Unknown error")
}

func (auth *OktaApiAuth) verifyPushFactor(stateToken string, factorsPush []interface{}) (err error) {
	var res map[string]interface{}
PUSH:
	for count, factor := range factorsPush {
		fid := factor.(map[string]interface{})["id"].(string)
		provider := factor.(map[string]interface{})["provider"].(string)
		res, err = auth.doAuth(fid, stateToken)
		if err != nil {
			if count == len(factorsPush)-1 {
				_, _ = auth.cancelAuth(stateToken)
				return err
			} else {
				continue
			}
		}
		checkCount := 0
		for res["factorResult"] == "WAITING" {
			// Reached only when "push" MFA is used
			checkCount++
			if checkCount > auth.ApiConfig.MFAPushMaxRetries {
				log.Warningf("%s push MFA timed out", provider)
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return errors.New("Push MFA timeout")
				} else {
					continue PUSH
				}
			}
			time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds) * time.Second)
			res, err = auth.doAuth(fid, stateToken)
			if err != nil {
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return err
				} else {
					continue PUSH
				}
			}
		}
		if _, ok := res["status"]; ok {
			if res["status"] == "SUCCESS" {
				log.Infof("authenticated with %s push MFA", provider)
				return nil
			} else {
				// Reached only when "push" MFA is used
				log.Warningf("%s push MFA authentication failed: %s",
					provider,
					res["factorResult"])
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return errors.New("Push MFA failed")
				}
			}
		}
	}
	return errors.New("Unknown error")
}

func (auth *OktaApiAuth) validateUserMFA(preAuthRes map[string]interface{}) (err error) {
	stateToken := getToken(preAuthRes)
	factorsTOTP, factorsPush := auth.getUserFactors(preAuthRes)

	if auth.UserConfig.Passcode != "" {
		if err = auth.verifyTOTPFactor(stateToken, factorsTOTP); err != nil {
			if err.Error() != "Unknown error" {
				return err
			}
			goto ERR
		}
		return nil
	}

	if err = auth.verifyPushFactor(stateToken, factorsPush); err == nil {
		return nil
	} else if err.Error() != "Unknown error" {
		return err
	}

ERR:
	log.Errorf("unknown MFA error")
	_, _ = auth.cancelAuth(stateToken)
	return errors.New("Unknown error")
}

// Do a full authentication transaction: preAuth, doAuth (when needed), cancelAuth (when needed)
// returns nil if has been validated by Okta API, an error otherwise
func (auth *OktaApiAuth) Auth() error {
	log.Infof("Authenticating")
	preAuthRes, err := auth.preChecks()
	if err != nil {
		return err
	}
	var status string
	if st, ok := preAuthRes["status"]; ok {
		status = st.(string)

		switch status {
		case "SUCCESS":
			if auth.ApiConfig.MFARequired {
				log.Warningf("allowed without MFA but MFA is required - rejected")
				return errors.New("MFA required")
			} else {
				return nil
			}

		case "LOCKED_OUT":
			log.Warningf("is locked out")
			return errors.New("User locked out")

		case "PASSWORD_EXPIRED":
			log.Warningf("password is expired")
			if stateToken := getToken(preAuthRes); stateToken != "" {
				_, _ = auth.cancelAuth(stateToken)
			}
			return errors.New("User password expired")

		case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
			log.Warningf("needs to enroll first")
			if stateToken := getToken(preAuthRes); stateToken != "" {
				_, _ = auth.cancelAuth(stateToken)
			}
			return errors.New("Needs to enroll")

		case "MFA_REQUIRED", "MFA_CHALLENGE":
			log.Debugf("checking second factor")
			return auth.validateUserMFA(preAuthRes)

		default:
			log.Errorf("unknown preauth status: %s", status)
			if stateToken := getToken(preAuthRes); stateToken != "" {
				_, _ = auth.cancelAuth(stateToken)
			}
			return errors.New("Unknown preauth status")
		}
	}

	if stateToken := getToken(preAuthRes); stateToken != "" {
		_, _ = auth.cancelAuth(stateToken)
	}
	log.Errorf("missing preauth status")
	return errors.New("Missing preauth status")
}
