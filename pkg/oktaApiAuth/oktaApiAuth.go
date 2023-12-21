package oktaApiAuth

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const userAgent string = "Mozilla/5.0 (Linux; x86_64) OktaOpenVPN/2.1.0"

// Contains the configuration for the Okta API connection
// Those configuration options are read from api.ini
type OktaAPIConfig struct {
	// Okta API server url, ie https://example.oktapreview.com
	Url string

	// Your (company's) Okta API token
	Token string

	// The suffix to be added to your users names:
	// ie if UsernameSuffix = "example.com" and your user logs in with "dade.murphy"
	// the validator will try to authenticate for "dade.murphy@example.com"
	UsernameSuffix string

	// A list of valid SSL public key fingerprint to validate the Okta API server certificate against
	AssertPin []string

	// Is MFA Required for all users. If yes and Okta authenticates the user without MFA (not configured)
	// the validator will reject it.
	MFARequired bool // default: false

	// Do not require usernames to come from client-side SSL certificates
	AllowUntrustedUsers bool // default: false

	// Number of retries when waiting for MFA result
	MFAPushMaxRetries int // default = 20

	// Number of seconds to wait between MFA result retrieval tries
	MFAPushDelaySeconds int // default = 3

	// List (comma separated) of groups allowed to connect
	AllowedGroups string
}

// User credentials and informations
type OktaUserConfig struct {
	Username string
	Password string
	Passcode string
	ClientIp string
}

type OktaApiAuth struct {
	ApiConfig  *OktaAPIConfig
	UserConfig *OktaUserConfig
	pool       *http.Client
	userAgent  string
}

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

// Prepare an http client with a safe TLS config
// validate the server public key against our list of pinned key fingerprint
func (auth *OktaApiAuth) InitPool() error {
	if rawURL, err := url.Parse(auth.ApiConfig.Url); err != nil {
		return err
	} else {
		var port string
		if port = rawURL.Port(); port == "" {
			port = "443"
		}
		// Connect to the server, fetch its public key and validate it against the
		// base64 digest in pinset slice
		tcpURL := fmt.Sprintf("%s:%s", rawURL.Hostname(), port)
		conn, err := tls.Dial("tcp", tcpURL, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Errorf("Error in Dial: %s", err)
			return err
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			if !cert.IsCA {
				// Compute public key base64 digest
				derPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return err
				}
				pubKeySha := sha256.Sum256(derPubKey)
				digest := base64.StdEncoding.EncodeToString([]byte(string(pubKeySha[:])))

				if !slices.Contains(auth.ApiConfig.AssertPin, digest) {
					log.Errorf("Refusing to authenticate because host %s failed %s\n%s\n%s",
						rawURL.Hostname(),
						"a TLS public key pinning check.",
						"Update your \"pinset.cfg\" file or ",
						"contact support@okta.com with this error message")
					return errors.New("Server pubkey does not match pinned keys")
				}
			}
		}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.2 safe cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			// TLS 1.3 cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	t := &http.Transport{
		MaxIdleConns:        5,
		MaxConnsPerHost:     5,
		MaxIdleConnsPerHost: 5,
		TLSClientConfig:     tlsCfg,
	}
	auth.pool = &http.Client{
		Timeout:   10 * time.Second,
		Transport: t,
	}
	return nil
}

func (auth *OktaApiAuth) Pool() *http.Client {
	return auth.pool
}

// Do an http request to the Okta API using the path and payload provided
func (auth *OktaApiAuth) oktaReq(method string, path string, data map[string]string) (a map[string]interface{}, err error) {
	u, _ := url.ParseRequestURI(auth.ApiConfig.Url)
	u.Path = fmt.Sprintf("/api/v1%s", path)

	ssws := fmt.Sprintf("SSWS %s", auth.ApiConfig.Token)
	headers := map[string]string{
		"User-Agent":    auth.userAgent,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Authorization": ssws,
	}
	if auth.UserConfig.ClientIp != "" {
		headers["X-Forwarded-For"] = auth.UserConfig.ClientIp
	}

	var r *http.Request
	var dataReader *bytes.Reader
	if method == http.MethodPost {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Errorf("Error marshaling request payload: %s", err)
			return nil, err
		}
		dataReader = bytes.NewReader(jsonData)
	} else {
		dataReader = bytes.NewReader([]byte{})
	}
	r, err = http.NewRequest(method, u.String(), dataReader)
	if err != nil {
		log.Errorf("Error creating http request: %s", err)
		return nil, err
	}
	for k, v := range headers {
		r.Header.Add(k, v)
	}
	resp, err := auth.pool.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	jsonBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading Okta API response: %s", err)
		return nil, err
	}
	// TODO: return an interface{} and have the "client" functions handle properly
	// what they expect
	if strings.HasPrefix(string(jsonBody), "{") {
		err = json.Unmarshal(jsonBody, &a)
		if err != nil {
			log.Errorf("Error unmarshaling Okta API response: %s", err)
			return nil, err
		}
	} else {
		var res []interface{}
		err = json.Unmarshal(jsonBody, &res)
		if err != nil {
			log.Errorf("Error unmarshaling Okta API response: %s", err)
			return nil, err
		}
		a = make(map[string]interface{})
		a["data"] = res
	}
	return a, nil
}

// Call the preauth Okta API endpoint
func (auth *OktaApiAuth) preAuth() (map[string]interface{}, error) {
	// https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
	data := map[string]string{
		"username": auth.UserConfig.Username,
		"password": auth.UserConfig.Password,
	}
	return auth.oktaReq(http.MethodPost, "/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *OktaApiAuth) doAuth(fid string, stateToken string) (map[string]interface{}, error) {
	// https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
	path := fmt.Sprintf("/authn/factors/%s/verify", fid)
	data := map[string]string{
		"fid":        fid,
		"stateToken": stateToken,
		"passCode":   auth.UserConfig.Passcode,
	}
	return auth.oktaReq(http.MethodPost, path, data)
}

// Cancel an authentication transaction
func (auth *OktaApiAuth) cancelAuth(stateToken string) (map[string]interface{}, error) {
	// https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
	data := map[string]string{
		"stateToken": stateToken,
	}
	return auth.oktaReq(http.MethodPost, "/authn/cancel", data)
}

func (auth *OktaApiAuth) checkAllowedGroups() error {
	// https://developer.okta.com/docs/reference/api/users/#request-parameters-8
	if auth.ApiConfig.AllowedGroups != "" {
		groupRes, err := auth.oktaReq(http.MethodGet, fmt.Sprintf("/users/%s/groups", auth.UserConfig.Username), nil)
		if err != nil {
			return err
		}
		var aGroups []string = strings.Split(auth.ApiConfig.AllowedGroups, ",")
		for _, uGroup := range groupRes["data"].([]interface{}) {
			gName := uGroup.(map[string]interface{})["profile"].(map[string]interface{})["name"].(string)
			if slices.Contains(aGroups, gName) {
				log.Debugf("is a member of AllowedGroup %s", gName)
				return nil
			}
		}
		return errors.New("Not mmember of an AllowedGroup")
	}
	return nil
}

func (auth *OktaApiAuth) getUserFactors(preAuthRes map[string]interface{}) (factorsTOTP []interface{}, factorsPush []interface{}) {
	factors := preAuthRes["_embedded"].(map[string]interface{})["factors"].([]interface{})

	for _, f := range factors {
		factorType := f.(map[string]interface{})["factorType"].(string)
		if factorType == "token:software:totp" {
			if auth.UserConfig.Passcode != "" {
				factorsTOTP = append(factorsTOTP, f)
			}
		} else if factorType == "push" {
			factorsPush = append(factorsPush, f)
		} else {
			log.Debugf("unsupported factortype: %s, skipping", factorType)
		}
	}
	return
}

func (auth *OktaApiAuth) preChecks() (map[string]interface{}, error) {
	err := auth.checkAllowedGroups()
	if err != nil {
		log.Errorf("allowed group verification error: %s", err)
		return nil, err
	}

	preAuthRes, err := auth.preAuth()
	if err != nil {
		log.Errorf("Error connecting to the Okta API: %s", err)
		return nil, err
	}

	if _, ok := preAuthRes["errorCauses"]; ok {
		log.Warningf("pre-authentication failed: %s", preAuthRes["errorSummary"])
		return nil, errors.New("pre-authentication failed")
	}
	return preAuthRes, nil
}

func getToken(preAuthRes map[string]interface{}) (st string) {
	if tok, ok := preAuthRes["stateToken"]; ok {
		st = tok.(string)
	}
	return st
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
