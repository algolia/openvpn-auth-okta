package oktaApiAuth

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

const (
	// Please update the fixtures if you modify one of this var !!
	oktaEndpoint string = "https://example.oktapreview.com"
	token        string = "12345"
	username     string = "dade.murphy@example.com"
	password     string = "test_password"
	passcode     string = "987654"
	ip           string = "1.2.3.4"
	stateToken   string = "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb"
	pushFID      string = "opf3hkfocI4JTLAju0g4"
	totpFID      string = "ostfm3hPNYSOIOIVTQWY"
	// validPinset has been computed using:
	/*
	   cat testing/fixtures/server.crt |\
	   	openssl x509 -noout -pubkey |\
	   	openssl rsa	-pubin -outform der 2>/dev/null |\
	   	openssl dgst -sha256 -binary | base64
	*/
	tlsHost       string = "127.0.0.1"
	tlsPort       string = "1443"
	validPinset   string = "j69yToSVkR6G7RKEc0qvsA6MysH+luI3wBIihDA20nI="
	invalidPinset string = "ABCDEF"
)

// Computed with:
/*
echo -n | openssl s_client -connect example.oktapreview.com:443 2>/dev/null |\
 openssl x509 -noout -pubkey |\
 openssl rsa	-pubin -outform der 2>/dev/null |\
 openssl dgst -sha256 -binary | base64
*/
var pin []string = []string{"SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="}

type authTest struct {
	testName     string
	mfaRequired  bool
	passcode     string
	requests     []authRequest
	unmatchedReq bool
	err          error
}

type setupTest struct {
	testName string
	requests []authRequest
	err      error
}

type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}

func TestOktaReq(t *testing.T) {
	defer gock.Off()
	// Uncomment the following line to see HTTP requests intercepted by gock
	//gock.Observe(gock.DumpRequest)

	tests := []setupTest{
		{
			"invalid json response - failure",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"invalid.json",
				},
			},
			fmt.Errorf("invalid character '-' looking for beginning of object key string"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.Flush()

			apiCfg := &OktaAPIConfig{
				Url:                 oktaEndpoint,
				Token:               token,
				UsernameSuffix:      "algolia.com",
				AssertPin:           pin,
				MFARequired:         false,
				AllowUntrustedUsers: true,
				MFAPushMaxRetries:   20,
				MFAPushDelaySeconds: 3,
			}
			userCfg := &OktaUserConfig{
				Username: username,
				Password: password,
				Passcode: "",
				ClientIp: ip,
			}

			for _, req := range test.requests {
				reqponseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)
				l = l.Post(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", ip).
					MatchType("json").
					JSON(req.payload)
				l.Reply(req.httpStatus).
					File(reqponseFile)
			}

			a := NewOktaApiAuth()
			assert.NotNil(t, a)
			a.ApiConfig = apiCfg
			a.UserConfig = userCfg
			err := a.InitPool()
			assert.Nil(t, err)
			gock.InterceptClient(a.pool)
			// Lets ensure we wont reach the real okta API
			gock.DisableNetworking()
			_, err = a.oktaReq(http.MethodPost, test.requests[0].path, test.requests[0].payload)
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

type poolTest struct {
	testName string
	host     string
	port     string
	pinset   []string
	err      error
}

func startTLS(t *testing.T) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("This is an example server.\n"))
	})
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	s := http.Server{
		Addr:         fmt.Sprintf("%s:%s", tlsHost, tlsPort),
		Handler:      mux,
		TLSConfig:    cfg,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	err := s.ListenAndServeTLS("../../testing/fixtures/utils/server.crt",
		"../../testing/fixtures/utils/server.key")
	assert.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
}

func TestInitPool(t *testing.T) {
	invalidHost := "invalid{host"
	invalidHostErr := fmt.Sprintf("parse \"https://%s:%s\": invalid character \"{\" in host name",
		invalidHost,
		tlsPort)

	tests := []poolTest{
		{
			"Test valid pinset",
			tlsHost,
			tlsPort,
			[]string{validPinset},
			nil,
		},

		{
			"Test invalid pinset",
			tlsHost,
			tlsPort,
			[]string{invalidPinset},
			fmt.Errorf("Server pubkey does not match pinned keys"),
		},

		{
			"Test unreachable host",
			tlsHost,
			"1444",
			[]string{},
			fmt.Errorf(fmt.Sprintf("dial tcp %s:1444: connect: connection refused", tlsHost)),
		},

		{
			"Test invalid url",
			invalidHost,
			tlsPort,
			[]string{},
			fmt.Errorf(invalidHostErr),
		},
	}

	go func() {
		startTLS(t)
	}()

	time.Sleep(1 * time.Second)
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			a := NewOktaApiAuth()
			a.ApiConfig.Url = fmt.Sprintf("https://%s:%s", test.host, test.port)
			a.ApiConfig.AssertPin = test.pinset
			err := a.InitPool()
			if test.err == nil {
				if err != nil {
					t.Logf(err.Error())
				}
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

func TestAuth(t *testing.T) {
	defer gock.Off()
	//gock.Observe(gock.DumpRequest)

	/*
		all the JSON response files used here have been extracted from
			https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
			https://developer.okta.com/docs/reference/api/authn/#multifactor-authentication-operations
		with fatcor id and stateToken modifications
	*/
	authTests := []authTest{
		{
			"PreAuth with invalid token - failure",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusUnauthorized,
					"preauth_invalid_token.json",
				},
			},
			false,
			fmt.Errorf("pre-authentication failed"),
		},

		{
			"PreAuth with invalid creadential - failure",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusUnauthorized,
					"preauth_invalid_credentials.json",
				},
			},
			false,
			fmt.Errorf("pre-authentication failed"),
		},

		{
			"PreAuth with locked out user - failure",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusUnauthorized,
					"preauth_lockedout.json",
				},
			},
			false,
			fmt.Errorf("User locked out"),
		},

		{
			"PreAuth succeesful with no MFA required - success",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			false,
			nil,
		},

		{
			"PreAuth successful but MFA required - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			false,
			fmt.Errorf("MFA required"),
		},

		{
			"PreAuth with MFA enrollment needed - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_mfa_enroll.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			fmt.Errorf("Needs to enroll"),
		},

		{
			"PreAuth with unknown status - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_unknown_status.json",
				},
			},
			false,
			fmt.Errorf("Unknown preauth status"),
		},

		{
			"Auth with push MFA required - success",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_push_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			nil,
		},

		{
			"Auth with push MFA required - rejected",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_push_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_rejected_push.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			fmt.Errorf("MFA failed"),
		},

		{
			"Auth with push timeout - rejected",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_push_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},

				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			fmt.Errorf("MFA timeout"),
		},

		{
			"Auth with MFA required, HTTP err - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_push_mfa_required.json",
				},
			},
			true,
			fmt.Errorf("Post \"https://example.oktapreview.com/api/v1/authn/factors/opf3hkfocI4JTLAju0g4/verify\": gock: cannot match any request"),
		},

		{
			"Auth with push timeout err - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_push_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},
			},
			true,
			fmt.Errorf("Post \"https://example.oktapreview.com/api/v1/authn/factors/opf3hkfocI4JTLAju0g4/verify\": gock: cannot match any request"),
		},

		{
			"Auth with unknown factortype - failure",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_unknown_mfa_required.json",
				},
			},
			false,
			fmt.Errorf("Unknown error"),
		},

		{
			"Auth with TOTP MFA required - success",
			true,
			passcode,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_totp_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", totpFID),
					map[string]string{"fid": totpFID, "stateToken": stateToken, "passCode": passcode},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			nil,
		},

		{
			"Auth with TOTP MFA required, multi MFA allowed to sort - success",
			true,
			passcode,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_mfa_required_multi.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", totpFID),
					map[string]string{"fid": totpFID, "stateToken": stateToken, "passCode": passcode},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			nil,
		},

		{
			"Auth with invalid TOTP MFA - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_totp_mfa_required.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", totpFID),
					map[string]string{"fid": totpFID, "stateToken": stateToken, "passCode": passcode},
					http.StatusForbidden,
					"auth_invalid_totp.json",
				},
			},
			false,
			fmt.Errorf("Your passcode doesn't match our records. Please try again."),
		},

		{
			"PreAuth connection issue - failure",
			true,
			passcode,
			nil,
			true,
			fmt.Errorf("Post \"https://example.oktapreview.com/api/v1/authn\": gock: cannot match any request"),
		},
	}

	for _, test := range authTests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.CleanUnmatchedRequest()
			gock.Flush()

			apiCfg := &OktaAPIConfig{
				Url:                 oktaEndpoint,
				Token:               token,
				UsernameSuffix:      "algolia.com",
				AssertPin:           pin,
				MFARequired:         test.mfaRequired,
				AllowUntrustedUsers: true,
				MFAPushMaxRetries:   0,
				MFAPushDelaySeconds: 3,
			}
			userCfg := &OktaUserConfig{
				Username: username,
				Password: password,
				Passcode: test.passcode,
				ClientIp: ip,
			}

			for _, req := range test.requests {
				reqponseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)
				l = l.Post(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", ip).
					MatchType("json").
					JSON(req.payload)
				l.Reply(http.StatusOK).
					File(reqponseFile)
			}

			a := &OktaApiAuth{
				ApiConfig:  apiCfg,
				UserConfig: userCfg,
				userAgent:  userAgent,
			}
			err := a.InitPool()
			assert.Nil(t, err)

			gock.InterceptClient(a.pool)
			gock.DisableNetworking()
			err2 := a.Auth()
			if test.err == nil {
				assert.Nil(t, err2)
			} else {
				assert.Equal(t, test.err.Error(), err2.Error())
			}
			if !test.unmatchedReq {
				assert.False(t, gock.HasUnmatchedRequest())
			}
			assert.False(t, gock.IsPending())
			assert.True(t, gock.IsDone())
		})
	}
}
