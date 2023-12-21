package oktaApiAuth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestCheckAllowedGroups(t *testing.T) {
	defer gock.Off()
	// Uncomment the following line to see HTTP requests intercepted by gock
	//gock.Observe(gock.DumpRequest)

	tests := []allowedGroupsTest{
		{
			"invalid json response - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"invalid_groups.json",
				},
			},
			"test1, test2",
			fmt.Errorf("invalid character '-' in numeric literal"),
		},
		{
			"Member of AllowedGroups - success",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"groups.json",
				},
			},
			"Cloud App Users, test2",
			nil,
		},
		{
			"Not member of AllowedGroups - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"groups.json",
				},
			},
			"test1, test2",
			fmt.Errorf("Not mmember of an AllowedGroup"),
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
				AllowedGroups:       test.allowedGroups,
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
				l = l.Get(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", ip).
					MatchType("json")
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
			err = a.checkAllowedGroups()
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
