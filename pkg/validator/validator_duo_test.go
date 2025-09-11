// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validator

import (
	"net/http"
	"testing"
	_ "unsafe"

	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/duoAuthApi"
)

//go:linkname getDuoPool gopkg.in/algolia/openvpn-auth-okta.v2/pkg/duoAuthApi.(*DuoAuthApi).getPool
func getDuoPool(*duoAuthApi.DuoAuthApi) *http.Client

/*
func TestDuoAuthenticate(t *testing.T) {
	defer gock.Off()
	//gock.Observe(gock.DumpRequest)
	tests := []testAuthenticate{
		{
			"Untrusted user - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid-okta.cfg",
			false,
			nil,
			false,
			"User not trusted",
		},

		{
			"Valid user - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid-okta.cfg",
			true,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{
						"username": fmt.Sprintf("%s@example.com", setupEnv["username"]),
						"password": setupEnv["password"],
					},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			true,
			"",
		},

		{
			"Invalid user - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid-okta.cfg",
			true,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{
						"username": fmt.Sprintf("%s@example.com", setupEnv["username"]),
						"password": setupEnv["password"],
					},
					http.StatusUnauthorized,
					"preauth_invalid_token.json",
				},
			},
			false,
			"Authentication failed",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.Flush()

			for _, req := range test.requests {
				responseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)
				l = l.Post(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", setupEnv["untrusted_ip"]).
					MatchType("json").
					JSON(req.payload)
				l.Reply(req.httpStatus).
					File(responseFile)
			}

			setEnv(setupEnv)
			v := New()
			v.configFile = test.cfgFile
			v.pinsetFile = test.pinsetFile
			ret := v.Setup(true, nil, nil)
			unsetEnv(setupEnv)
			assert.True(t, ret)
			v.usernameTrusted = test.userTrusted
			v.api.GetApiConfig().MFARequired = false
			gock.InterceptClient(getOktaPool(v.api.(*oktaAuthApi.OktaAuthApi)))
			gock.DisableNetworking()
			err := v.Authenticate()
			assert.Equal(t, test.ret, v.isUserValid)
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
*/

func TestDuoSetup(t *testing.T) {
	/*
		New version: TODO
		tests := []testSetup{
			{
				"Duo - Invalid url in config file / deferred - false",
				"../../testing/fixtures/validator/invalid_duo_url.ini",
				"../../testing/fixtures/validator/valid-duo.cfg",
				true,
				setupEnv,
				nil,
				false,
			},
			{
				"Duo - Valid config file / valid env / deferred - true",
				"../../testing/fixtures/validator/valid-duo.ini",
				"../../testing/fixtures/validator/valid-duo.cfg",
				true,
				setupEnv,
				nil,
				true,
			},
			{
				"Duo - Valid config file / valid env / via-env - true",
				"../../testing/fixtures/validator/valid-duo.ini",
				"../../testing/fixtures/validator/valid-duo.cfg",
				false,
				setupEnv,
				nil,
				true,
			},
			{
				"Duo - Valid config file / valid via-file / via-env - true",
				"../../testing/fixtures/validator/valid-duo.ini",
				"../../testing/fixtures/validator/valid-duo.cfg",
				false,
				nil,
				[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
				true,
			},
		}
		testSetups(tests, t)
	*/
}
