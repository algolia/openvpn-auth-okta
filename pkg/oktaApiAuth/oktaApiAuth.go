// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaApiAuth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/go-playground/validator/v10"
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

func (auth *OktaApiAuth) verifyTOTPFactor(stateToken string, factorsTOTP []AuthFactor) (err error) {
	// If no passcode is provided, this is a noop
	for count, factor := range factorsTOTP {
		authRes, err := auth.doAuthFirstStep(factor, count, len(factorsTOTP), stateToken)
		if err != nil {
			if err.Error() == "continue" {
				continue
			} else {
				return err
			}
		}

		if authRes.Status == "SUCCESS" {
			log.Infof("authenticated with %s TOTP MFA", factor.Provider)
			return nil
		}

		if count == len(factorsTOTP)-1 {
			log.Errorf("%s TOTP MFA authentication failed: %s",
				factor.Provider,
				authRes.Result)
			_, _ = auth.cancelAuth(stateToken)
			return errors.New("TOTP MFA failed")
		}
		log.Warningf("%s TOTP MFA authentication failed: %s",
			factor.Provider,
			authRes.Result)
	}
	// We'll only be there if a passcode is provided and no TOTP factor is available
	return errors.New("Unknown error")
}

func (auth *OktaApiAuth) verifyPushFactor(stateToken string, factorsPush []AuthFactor) (err error) {
	validate := validator.New(validator.WithRequiredStructEnabled())
PUSH:
	for count, factor := range factorsPush {
		authRes, err := auth.doAuthFirstStep(factor, count, len(factorsPush), stateToken)
		if err != nil {
			if err.Error() == "continue" {
				continue
			} else {
				return err
			}
		}

		checkCount := 0
		for authRes.Result == "WAITING" {
			checkCount++
			if checkCount > auth.ApiConfig.MFAPushMaxRetries {
				log.Warningf("%s push MFA timed out", factor.Provider)
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return errors.New("Push MFA timeout")
				} else {
					continue PUSH
				}
			}

			time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds) * time.Second)

			apiRes, err := auth.doAuth(factor.Id, stateToken)
			if err != nil {
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return err
				} else {
					continue
				}
			}

			err = json.Unmarshal(apiRes, &authRes)
			if err != nil {
				log.Errorf("Error unmarshaling Okta API response: %s", err)
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return err
				} else {
					continue
				}
			}
			err = validate.Struct(authRes)
			if err != nil {
				log.Errorf("Error unmarshaling Okta API response: %s", err)
				if count == len(factorsPush)-1 {
					_, _ = auth.cancelAuth(stateToken)
					return errors.New("Push MFA failed")
				} else {
					continue
				}
			}
		}

		if authRes.Status == "SUCCESS" {
			log.Infof("authenticated with %s push MFA", factor.Provider)
			return nil
		}

		if count == len(factorsPush)-1 {
			log.Errorf("%s push MFA authentication failed: %s",
				factor.Provider,
				authRes.Result)
			_, _ = auth.cancelAuth(stateToken)
			return errors.New("Push MFA failed")
		}
		log.Warningf("%s push MFA authentication failed: %s",
			factor.Provider,
			authRes.Result)
	}
	return errors.New("Unknown error")
}

func (auth *OktaApiAuth) validateUserMFA(preAuthRes PreAuthResponse) (err error) {
	factorsTOTP, factorsPush := auth.getUserFactors(preAuthRes)

	if auth.UserConfig.Passcode != "" {
		if err = auth.verifyTOTPFactor(preAuthRes.Token, factorsTOTP); err != nil {
			if err.Error() != "Unknown error" {
				return err
			}
			goto ERR
		}
		return nil
	}

	if err = auth.verifyPushFactor(preAuthRes.Token, factorsPush); err == nil {
		return nil
	} else if err.Error() != "Unknown error" {
		return err
	}

ERR:
	log.Errorf("unknown MFA error")
	_, _ = auth.cancelAuth(preAuthRes.Token)
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

	switch preAuthRes.Status {
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
		if preAuthRes.Token != "" {
			_, _ = auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("User password expired")

	case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
		log.Warningf("needs to enroll first")
		if preAuthRes.Token != "" {
			_, _ = auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("Needs to enroll")

	case "MFA_REQUIRED", "MFA_CHALLENGE":
		log.Debugf("checking second factor")
		return auth.validateUserMFA(preAuthRes)

	default:
		log.Errorf("unknown preauth status: %s", preAuthRes.Status)
		if preAuthRes.Token != "" {
			_, _ = auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("Unknown preauth status")
	}
}
