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
	"sort"
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
		port := rawURL.Port()
		if port == "" {
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
					log.Errorf("Refusing to authenticate because host %s failed %s\n%s",
						rawURL.Hostname(),
						"a TLS public key pinning check.",
						"Please contact support@okta.com with this error message")
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

// Do a POST http request to the Okta API using the path and payload provided
func (auth *OktaApiAuth) oktaReq(path string, data map[string]string) (a map[string]interface{}, err error) {
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

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Errorf("Error marshaling request payload: %s", err)
		return nil, err
	}
	r, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonData))
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
	err = json.Unmarshal(jsonBody, &a)
	if err != nil {
		log.Errorf("Error unmarshaling Okta API response: %s", err)
		return nil, err
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
	return auth.oktaReq("/authn", data)
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
	return auth.oktaReq(path, data)
}

// Cancel an authentication transaction
func (auth *OktaApiAuth) cancelAuth(stateToken string) (map[string]interface{}, error) {
	// https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
	data := map[string]string{
		"stateToken": stateToken,
	}
	return auth.oktaReq("/authn/cancel", data)
}

// Do a full authentication transaction: preAuth, doAuth (when needed), cancelAuth (when needed)
// returns nil if has been validated by Okta API, an error otherwise
func (auth *OktaApiAuth) Auth() error {
	var status string
	log.Infof("[%s] Authenticating", auth.UserConfig.Username)
	retp, err := auth.preAuth()
	if err != nil {
		log.Errorf("[%s] Error connecting to the Okta API: %s", auth.UserConfig.Username, err)
		return err
	}

	if _, ok := retp["errorCauses"]; ok {
		log.Warningf("[%s] pre-authentication failed: %s", auth.UserConfig.Username, retp["errorSummary"])
		return errors.New("pre-authentication failed")
	}
	if st, ok := retp["status"]; ok {
		status = st.(string)
		stateToken := ""
		if tok, ok := retp["stateToken"]; ok {
			stateToken = tok.(string)
		}

		switch status {
		case "SUCCESS":
			if auth.ApiConfig.MFARequired {
				log.Warningf("[%s] allowed without MFA and MFA is required - rejected", auth.UserConfig.Username)
				return errors.New("MFA required")
			} else {
				return nil
			}

		case "LOCKED_OUT":
			log.Warningf("[%s] user is locked out", auth.UserConfig.Username)
			return errors.New("User locked out")

		case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
			log.Warningf("[%s] user needs to enroll first", auth.UserConfig.Username)
			_, _ = auth.cancelAuth(stateToken)
			return errors.New("Needs to enroll")

		case "MFA_REQUIRED", "MFA_CHALLENGE":
			log.Debugf("[%s] user password validates, checking second factor", auth.UserConfig.Username)

			factors := retp["_embedded"].(map[string]interface{})["factors"].([]interface{})
			supportedFactorTypes := []string{"token:software:totp", "push"}
			var res map[string]interface{}

			// When a TOTP is provided ensure that the proper Okta factor id used first, fallback to push
			// use first push when TOTP is empty
			var preferedFactor string = "push"
			if auth.UserConfig.Passcode != "" {
				preferedFactor = "token:software:totp"
			}
			sort.Slice(factors, func(i, j int) bool {
				return factors[i].(map[string]interface{})["factorType"].(string) == preferedFactor
			})

			for _, factor := range factors {
				factorType := factor.(map[string]interface{})["factorType"].(string)
				if !slices.Contains(supportedFactorTypes, factorType) {
					log.Debugf("Unsupported factortype: %s, skipping", factorType)
					continue
				}
				fid := factor.(map[string]interface{})["id"].(string)
				res, err = auth.doAuth(fid, stateToken)
				if err != nil {
					_, _ = auth.cancelAuth(stateToken)
					return err
				}
				checkCount := 0
				for res["factorResult"] == "WAITING" {
					time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds) * time.Second)
					res, err = auth.doAuth(fid, stateToken)
					if err != nil {
						_, _ = auth.cancelAuth(stateToken)
						return err
					}
					if checkCount++; checkCount > auth.ApiConfig.MFAPushMaxRetries {
						log.Warningf("[%s] User MFA push timed out", auth.UserConfig.Username)
						_, _ = auth.cancelAuth(stateToken)
						return errors.New("MFA timeout")
					}
				}
				if _, ok := res["status"]; ok {
					if res["status"] == "SUCCESS" {
						log.Infof("[%s] User is now authenticated with MFA via Okta API", auth.UserConfig.Username)
						return nil
					} else {
						log.Warningf("[%s] User MFA push failed: %s", auth.UserConfig.Username, res["factorResult"])
						_, _ = auth.cancelAuth(stateToken)
						return errors.New("MFA failed")
					}
				}
			}
			if _, ok := res["errorCauses"]; ok {
				cause := res["errorCauses"].([]interface{})[0]
				errorSummary := cause.(map[string]interface{})["errorSummary"].(string)
				log.Warningf("[%s] User MFA token authentication failed: %s", auth.UserConfig.Username, errorSummary)
				return errors.New(errorSummary)
			}
			return errors.New("Unknown error")

		default:
			log.Errorf("Unknown preauth status: %s", status)
			return errors.New("Unknown preauth status")
		}
	}

	log.Warningf("[%s] User is not allowed to authenticate: %s", auth.UserConfig.Username, status)
	return errors.New("Not allowed")
}
