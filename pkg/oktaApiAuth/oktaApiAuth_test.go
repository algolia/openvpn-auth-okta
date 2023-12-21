package oktaApiAuth

import (
	"fmt"
	"net/http"
	"testing"

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
			"Not member of allowed groups - failure",
			false,
			"",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"groups.json",
				},
			},
			false,
			"test1, test2",
			fmt.Errorf("Not mmember of an AllowedGroup"),
		},

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
			"",
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
			"",
			fmt.Errorf("pre-authentication failed"),
		},

		{
			"PreAuth with invalid response (missing status) - failure",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusUnauthorized,
					"preauth_missing_status.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("Missing preauth status"),
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
			"",
			fmt.Errorf("User locked out"),
		},

		{
			"PreAuth with password expired - failure",
			false,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_password_expired.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("User password expired"),
		},

		{
			"PreAuth successful with no MFA required - success",
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
			"",
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
			"",
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
			"",
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
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
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
			"",
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
			"",
			fmt.Errorf("Push MFA failed"),
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
			"",
			fmt.Errorf("Push MFA timeout"),
		},

		{
			"Auth with 2 push providers, first timeout - success",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_2_push_mfa_providers.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			"",
			nil,
		},

		{
			"Auth with 2 push providers, first invalid response - success",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_2_push_mfa_providers.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"invalid.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			"",
			nil,
		},

		{
			"Auth with 2 push providers, first invalid response after waiting - success",
			true,
			"",
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_2_push_mfa_providers.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_waiting.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"invalid.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", pushFID),
					map[string]string{"fid": pushFID, "stateToken": stateToken, "passCode": ""},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			"",
			nil,
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
			"",
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
			"",
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
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
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
			"",
			nil,
		},

		{
			"Auth with TOTP MFA, invalid answer - failure",
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
					"invalid.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("invalid character '-' looking for beginning of object key string"),
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
			"",
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
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("TOTP MFA failed"),
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
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("TOTP MFA failed"),
		},

		{
			"Auth with TOTP MFA missing status - failure",
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
					"auth_missing_status.json",
				},
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			false,
			"",
			fmt.Errorf("Unknown error"),
		},

		{
			"Auth with 2 TOTP MFA, first invalid answer - success",
			true,
			passcode,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"preauth_2_totp_providers.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", "rejected"),
					map[string]string{"fid": "rejected", "stateToken": stateToken, "passCode": passcode},
					http.StatusOK,
					"invalid.json",
				},
				{
					fmt.Sprintf("/api/v1/authn/factors/%s/verify", totpFID),
					map[string]string{"fid": totpFID, "stateToken": stateToken, "passCode": passcode},
					http.StatusOK,
					"auth_success.json",
				},
			},
			false,
			"",
			nil,
		},

		{
			"PreAuth connection issue - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/api/v1/authn/cancel",
					map[string]string{"stateToken": stateToken},
					http.StatusOK,
					"empty.json",
				},
			},
			true,
			"",
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
				MFAPushMaxRetries:   1,
				MFAPushDelaySeconds: 3,
				AllowedGroups:       test.allowedGroups,
			}
			userCfg := &OktaUserConfig{
				Username: username,
				Password: password,
				Passcode: test.passcode,
				ClientIp: ip,
			}

			for _, req := range test.requests {
				responseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)

				if test.allowedGroups != "" {
					l = l.Get(req.path).
						MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
						MatchHeader("X-Forwarded-For", ip).
						MatchType("json")
					l.Reply(req.httpStatus).
						File(responseFile)
				} else {
					l = l.Post(req.path).
						MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
						MatchHeader("X-Forwarded-For", ip).
						MatchType("json").
						JSON(req.payload)
					l.Reply(http.StatusOK).
						File(responseFile)
				}
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
			if test.testName == "PreAuth connection issue - failure" {
				assert.True(t, gock.IsPending())
				assert.False(t, gock.IsDone())
			} else {
				assert.False(t, gock.IsPending())
				assert.True(t, gock.IsDone())
			}
		})
	}
}
