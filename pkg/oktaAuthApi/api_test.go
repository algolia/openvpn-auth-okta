// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaAuthApi

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/OAtest"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
	"gopkg.in/h2non/gock.v1"
)

type poolTest struct {
	testName string
	host     string
	port     string
	pinset   []string
	errMsg   string
}

type setupTest struct {
	testName string
	requests []authRequest
	errMsg   string
}

func TestOktaSetup(t *testing.T) {
	invalidHost := "invalid{host"
	invalidHostErr := fmt.Sprintf("parse \"https://%s:%s\": invalid character \"{\" in host name",
		invalidHost,
		OAtest.TLSPort)

	tests := []poolTest{
		{
			"Test valid pinset",
			OAtest.TLSHost,
			OAtest.TLSPort,
			[]string{OAtest.TLSValidPinset},
			"",
		},

		{
			"Test invalid pinset",
			OAtest.TLSHost,
			OAtest.TLSPort,
			[]string{OAtest.TLSInvalidPinset},
			"Server pubkey does not match pinned keys",
		},

		{
			"Test unreachable host",
			OAtest.TLSHost,
			"1444",
			[]string{},
			fmt.Sprintf("dial tcp %s:1444: connect: connection refused", OAtest.TLSHost),
		},

		{
			"Test invalid url",
			invalidHost,
			OAtest.TLSPort,
			[]string{},
			invalidHostErr,
		},
	}

	srv := OAtest.StartTestHttpsServer(t)

	time.Sleep(1 * time.Second)
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			a := New()
			a.ApiConfig.Url = fmt.Sprintf("https://%s:%s", test.host, test.port)
			a.ApiConfig.AssertPin = test.pinset
			err := a.Setup()
			if test.errMsg == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
	if err := srv.Close(); err != nil {
		panic(err) // failure/timeout shutting down the server gracefully
	}
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
					http.StatusInternalServerError,
					"invalid.json",
				},
			},
			"",
		},
		{
			"invalid payload - failure",
			[]authRequest{
				{
					"/api/v1/authn",
					nil,
					http.StatusInternalServerError,
					"invalid.json",
				},
			},
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.Flush()

			apiCfg := &authApi.APIConfig{
				Url:                 oktaEndpoint,
				UsernameSuffix:      "algolia.com",
				AssertPin:           pin,
				MFARequired:         false,
				AllowUntrustedUsers: true,
			}
			userCfg := &authApi.APIUserConfig{
				Username: username,
				Password: password,
				Passcode: "",
				ClientIp: ip,
			}
			providerCfg := &ProviderApiConfig{
				Token:               token,
				MFAPushMaxRetries:   20,
				MFAPushDelaySeconds: 3,
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

			a := New()
			assert.NotNil(t, a)
			a.ApiConfig = apiCfg
			a.UserConfig = userCfg
			a.ProviderConfig = providerCfg
			err := a.Setup()
			assert.Nil(t, err)
			gock.InterceptClient(a.pool)
			// Lets ensure we wont reach the real okta API
			gock.DisableNetworking()
			_, _, err = a.oktaReq(http.MethodPost, test.requests[0].path, test.requests[0].payload)
			if test.errMsg == "" {
				assert.Nil(t, err)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}
