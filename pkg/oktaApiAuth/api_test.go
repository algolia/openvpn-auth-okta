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
	err      error
}

type setupTest struct {
	testName string
	requests []authRequest
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
			a := New()
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
			nil,
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
			nil,
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
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
