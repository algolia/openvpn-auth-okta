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
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

type allowedGroupsTest struct {
	testName      string
	requests      []authRequest
	allowedGroups string
	token         string
	errMsg        string
}

func TestCheckAllowedGroups(t *testing.T) {
	defer gock.Off()
	// Uncomment the following line to see HTTP requests intercepted by gock
	//gock.Observe(gock.DumpRequest)

	tests := []allowedGroupsTest{
		{
			"no response - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": "TEST", "password": "TEST"},
					http.StatusOK,
					"groups_invalid_json.json",
				},
			},
			"test1, test2",
			"FAKE_TOKEN",
			"Get \"https://example.oktapreview.com/api/v1/users/dade.murphy@example.com/groups\": gock: cannot match any request",
		},
		{
			"invalid json response - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"groups_invalid_json.json",
				},
			},
			"test1, test2",
			token,
			"invalid character '-' in numeric literal",
		},
		{
			"invalid HTTP status code - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusInternalServerError,
					"groups_invalid_json.json",
				},
			},
			"test1, test2",
			token,
			"invalid HTTP status code",
		},
		{
			"invalid token - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusUnauthorized,
					"groups_invalid_token.json",
				},
			},
			"test1, test2",
			token,
			"invalid HTTP status code",
		},
		{
			"missing group name - failure",
			[]authRequest{
				{
					fmt.Sprintf("/api/v1/users/%s/groups", username),
					map[string]string{"username": username, "password": password},
					http.StatusOK,
					"groups_no_name.json",
				},
			},
			"Cloud App Users, test2",
			token,
			"invalid group list return by API",
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
			token,
			"",
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
			token,
			"Not mmember of an AllowedGroup",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.Flush()

			apiCfg := &OktaAPIConfig{
				Url:                 oktaEndpoint,
				Token:               test.token,
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

			a := New()
			assert.NotNil(t, a)
			a.ApiConfig = apiCfg
			a.UserConfig = userCfg
			err := a.InitPool()
			assert.NoError(t, err)
			gock.InterceptClient(a.pool)
			// Lets ensure we wont reach the real okta API
			gock.DisableNetworking()
			err = a.checkAllowedGroups()
			if test.errMsg == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}
