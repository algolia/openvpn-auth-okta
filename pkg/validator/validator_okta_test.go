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
	"fmt"
	"net/http"
	"os"
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/oktaAuthApi"
	"gopkg.in/h2non/gock.v1"
)

//go:linkname getOktaPool gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaAuthApi.(*OktaAuthApi).getPool
func getOktaPool(*oktaAuthApi.OktaAuthApi) *http.Client

func TestOktaAuthenticate(t *testing.T) {
	defer gock.Off()
	//gock.Observe(gock.DumpRequest)
	tests := []testAuthenticate{
		{
			"Untrusted user - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			false,
			"User not trusted",
		},

		{
			"Valid user - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
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
			"../../testing/fixtures/validator/valid.cfg",
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
				reqponseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)
				l = l.Post(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", setupEnv["untrusted_ip"]).
					MatchType("json").
					JSON(req.payload)
				l.Reply(req.httpStatus).
					File(reqponseFile)
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

func TestOktaSetup(t *testing.T) {
	tests := []testSetup{
		{
			"Invalid url in config file / deferred - false",
			"../../testing/fixtures/validator/invalid_url.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / deferred - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Valid config file / valid env / deferred - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			true,
		},
		{
			"Invalid env / deferred - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			map[string]string{"auth_control_file": controlFile},
			nil,
			false,
		},
		{
			"Invalid pinset / deferred - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"MISSING",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / via-env - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			setupEnv,
			nil,
			false,
		},
		{
			"Valid config file / valid env / via-env - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			setupEnv,
			nil,
			true,
		},
		{
			"Invalid env / via-env - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			map[string]string{"auth_control_file": controlFile},
			nil,
			false,
		},
		{
			"Invalid pinset / via-env - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"MISSING",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / via-file - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			false,
		},
		{
			"Valid config file / valid via-file / via-env - true",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			true,
		},
		{
			"Invalid via-file / via-file - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/invalid_viafile.cfg"},
			false,
		},
		{
			"Invalid pinset / via-env - false",
			"../../testing/fixtures/validator/valid-okta.ini",
			"MISSING",
			true,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			false,
		},
	}

	_, _ = os.Create(controlFile)
	defer func() { _ = os.Remove(controlFile) }()

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			setEnv(test.env)
			v := New("INFO")
			v.configFile = test.cfgFile
			v.pinsetFile = test.pinsetFile
			ret := v.Setup(test.deferred, test.args, nil)
			unsetEnv(test.env)
			assert.Equal(t, test.ret, ret)
		})
	}
}
