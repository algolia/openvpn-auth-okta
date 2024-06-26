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
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

type errorTest struct {
	testName    string
	inputErrMsg string
	inputErr2   error
	count       int
	errMsg      string
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
			"",
		},

		{
			"Test invalid pinset",
			tlsHost,
			tlsPort,
			[]string{invalidPinset},
			"Server pubkey does not match pinned keys",
		},

		{
			"Test unreachable host",
			tlsHost,
			"1444",
			[]string{},
			fmt.Sprintf("dial tcp %s:1444: connect: connection refused", tlsHost),
		},

		{
			"Test invalid url",
			invalidHost,
			tlsPort,
			[]string{},
			invalidHostErr,
		},
	}

	go func() {
		startTLS(t)
	}()

	time.Sleep(1 * time.Second)
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			a := New()
			a.ApiConfig.Url = fmt.Sprintf("https://%s:%s", test.host, test.port)
			a.ApiConfig.AssertPin = test.pinset
			err := a.InitPool()
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

			a := New()
			assert.NotNil(t, a)
			a.ApiConfig = apiCfg
			a.UserConfig = userCfg
			err := a.InitPool()
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

func TestParseOktaError(t *testing.T) {
	nonWrappedLast := "non-wrapped error for last factor"
	nonWrapped := "non-wrapped error for first factor"
	tests := []errorTest{
		{
			"Test non-wrapped error for last factor",
			nonWrappedLast,
			nil,
			1,
			nonWrappedLast,
		},
		{
			"Test non-wrapped error for non-last factor",
			nonWrapped,
			nil,
			0,
			"",
		},
		{
			"Test wrapped error for last factor",
			nonWrappedLast,
			fmt.Errorf("ERROR"),
			1,
			"ERROR",
		},
		{
			"Test wrapped error for non-last factor",
			nonWrapped,
			fmt.Errorf("ERROR"),
			0,
			"",
		},
		{
			"Test no Error",
			"",
			nil,
			1,
			"",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			var inputErr error
			if test.inputErrMsg != "" {
				if test.inputErr2 != nil {
					inputErr = fmt.Errorf("%s %w", test.inputErrMsg, test.inputErr2)
				} else {
					inputErr = fmt.Errorf("%s", test.inputErrMsg)
				}
			}
			err := parseOktaError(inputErr, test.count, 2)
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
