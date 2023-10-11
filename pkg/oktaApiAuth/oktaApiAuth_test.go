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
)

// Computed with:
/*
echo -n | openssl s_client -connect example.oktapreview.com:443 2>/dev/null |\
 openssl x509 -noout -pubkey |\
 openssl rsa  -pubin -outform der 2>/dev/null |\
 openssl dgst -sha256 -binary | base64
*/
var pin []string = []string{"SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="}

type authTest struct {
  testName       string
  mfaRequired    bool
  passcode       string
  requests       []authRequest
  err            error
}

type authRequest struct {
  path           string
  payload        map[string]string
  httpStatus     int
  jsonResponseFile string
}

func TestAuth(t *testing.T) {
  defer gock.Off()
  gock.Observe(gock.DumpRequest)
  gock.DisableNetworking()

  /*
    all the response JSON file used here have been extracted from
      https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
      https://developer.okta.com/docs/reference/api/authn/#multifactor-authentication-operations
    with fatcor id and stateToken modifications
  */
  authTests := []authTest{
    {
      "Test PreAuth with invalid token - failure",
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
      fmt.Errorf("pre-authentication failed"),
    },

    {
      "Test PreAuth with invalid creadential - failure",
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
      fmt.Errorf("pre-authentication failed"),
    },

    {
      "Test PreAuth with locked out user - failure",
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
      fmt.Errorf("User locked out"),
    },

    {
      "Test PreAuth succeesful with no MFA required - success",
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
      nil,
    },

    {
      "Test PreAuth successful with MFA required - failure",
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
      fmt.Errorf("MFA required"),
    },

    {
      "Test PreAuth with MFA enrollment needed - failure",
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
      fmt.Errorf("Needs to enroll"),
    },

    {
      "Test Auth with push MFA required - success",
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
      nil,
    },

    {
      "Test Auth with push MFA required - rejected",
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
      fmt.Errorf("MFA failed"),
    },

    {
      "Test Auth with TOTP MFA required - success",
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
      nil,
    },

    {
      "Test Auth with invalid TOTP MFA - failure",
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
      fmt.Errorf("Your passcode doesn't match our records. Please try again."),
    },
  }

  for _, test := range authTests {
    t.Run(test.testName, func(t *testing.T) {
      gock.Clean()
      gock.Flush()

      apiCfg := &OktaAPI{
        Url: oktaEndpoint,
        Token: token,
        UsernameSuffix: "algolia.com",
        AssertPin: pin,
        MFARequired: test.mfaRequired,
        AllowUntrustedUsers: true,
        MFAPushMaxRetries: 20,
        MFAPushDelaySeconds: 3,
      }
      userCfg := &OktaUserConfig{
        Username: username,
        Password: fmt.Sprintf("%s%s", password, test.passcode),
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
        l.Reply(http.StatusOK).
          File(reqponseFile)
      }

      a, err := NewOktaApiAuth(apiCfg, userCfg)
      assert.Nil(t, err)
      gock.InterceptClient(a.pool)
      err2 := a.Auth()
      if test.err == nil {
        assert.Nil(t, err2)
      } else {
        assert.Equal(t, test.err.Error(), err2.Error())
      }
      assert.False(t, gock.HasUnmatchedRequest())
      assert.False(t, gock.IsPending())
      assert.True(t, gock.IsDone())
    })
  }
}
