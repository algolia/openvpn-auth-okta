// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package duoAuthApi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
	"gopkg.in/h2non/gock.v1"
)

var pin []string = []string{"QrT4//Lh+ukzff3/wJBIIJqejh2E4EQiaXGoBdI7eP0="}

const (
	// Please update the fixtures if you modify one of this var !!
	duoEndpoint string = "https://api.duosecurity.com"
	ikey        string = "01234"
	skey        string = "56789"
	username    string = "dade.murphy@example.com"
	password    string = "test_password"
	passcode    string = "987654"
	ip          string = "1.2.3.4"
	pushDevice  string = "opf3hkfocI4JTLAju0g4"
)

type authRequest struct {
	path             string
	method           string
	headers          map[string]string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}

type authTest struct {
	testName     string
	mfaRequired  bool
	passcode     string
	requests     []authRequest
	unmatchedReq bool
	fallback     bool
	errMsg       string
}

func commonAuthTest(authTests []authTest, t *testing.T) {
	defer gock.Off()
	// Uncomment the following line to see HTTP requests intercepted by gock
	//gock.Observe(gock.DumpRequest)
	for _, test := range authTests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.CleanUnmatchedRequest()
			gock.Flush()

			apiCfg := &authApi.APIConfig{
				Url:                 duoEndpoint,
				UsernameSuffix:      "algolia.com",
				AssertPin:           pin,
				MFARequired:         test.mfaRequired,
				AllowUntrustedUsers: true,
				TOTPFallbackToPush:  test.fallback,
			}
			userCfg := &authApi.APIUserConfig{
				Username: username,
				Password: password,
				Passcode: test.passcode,
				ClientIp: ip,
			}
			providerCfg := &ProviderApiConfig{
				Ikey:    ikey,
				Skey:    skey,
				Timeout: 30,
			}

			//t.Errorf("duoEnpoint: %s", duoEndpoint)
			for _, req := range test.requests {
				responseFile := fmt.Sprintf("../../testing/fixtures/duoApi/%s", req.jsonResponseFile)
				l := gock.New(duoEndpoint)

				if strings.ToUpper(req.method) == "GET" {
					l = l.Get(req.path).
						MatchHeader("User-Agent", "Algolia Bastion duo_api_golang/0.2.0").
						MatchHeader("Authorization", "^Basic .*").
						MatchHeader("Date", "")
					for k, v := range req.headers {
						l.MatchHeader(k, v)
					}
					l.Reply(req.httpStatus).
						File(responseFile)
					//t.Errorf("Req interceptor: %+v", l)
				} else {
					l = l.Post(req.path).
						MatchHeader("User-Agent", "Algolia Bastion duo_api_golang").
						MatchType("application/x-www-form-urlencoded")
					for k, v := range req.payload {
						l.BodyString(k + "=" + v)
					}
					for k, v := range req.headers {
						l.MatchHeader(k, v)
					}
					l.Reply(req.httpStatus).
						File(responseFile)
				}
			}

			a := &DuoAuthApi{
				ApiConfig:      apiCfg,
				UserConfig:     userCfg,
				ProviderConfig: providerCfg,
			}
			err := a.Setup()
			require.Nil(t, err, "DuoAuthApi.Setup failed")

			gock.InterceptClient(a.pool)
			gock.DisableNetworking()
			err = a.Auth()
			if test.errMsg == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
			if !test.unmatchedReq {
				assert.False(t, gock.HasUnmatchedRequest(), "Gock has unmatched requests")
			}
			assert.False(t, gock.IsPending(), "Pending Gock requests")
			assert.True(t, gock.IsDone(), "Gock is not  done")
			/*
				if !assert.False(t, gock.IsPending(), "Pending Gock requests") {
					t.Errorf("requests: %+v", test.requests)
				}
				if !assert.True(t, gock.IsDone(), "Gock is not  done") {
					t.Errorf("requests: %+v", test.requests)
				}
			*/
		})
	}
}

func TestDuoAuthCheck(t *testing.T) {
	authTests := []authTest{
		{
			"Check empty response - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{},
					map[string]string{},
					http.StatusUnauthorized,
					"empty.json",
				},
			},
			true,
			false,
			errCheckFailed.Error(),
		},
		{
			"Check error - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusUnauthorized,
					"check_error.json",
				},
			},
			true,
			false,
			errCheckFailed.Error(),
		},
		{
			"Check invalid response - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusUnauthorized,
					"invalid.json",
				},
			},
			true,
			false,
			errCheckFailed.Error(),
		},
	}
	commonAuthTest(authTests, t)

}

func TestDuoAuthPreAuth(t *testing.T) {
	authTests := []authTest{
		{
			"PreAuth invalid response - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"invalid.json",
				},
			},
			true,
			false,
			"invalid character '-' looking for beginning of object key string",
		},
		{
			"PreAuth FAIL status - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_fail_status.json",
				},
			},
			true,
			false,
			"error during Duo preAuth: Unknown error.",
		},
		{
			"PreAuth unknown result - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_unknown_result.json",
				},
			},
			true,
			false,
			authApi.ErrPreauthUnknownStatus.Error(),
		},
		{
			"PreAuth enroll result - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_enroll.json",
				},
			},
			true,
			false,
			authApi.ErrEnrollNeeded.Error(),
		},
		{
			"PreAuth deny result - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_denied.json",
				},
			},
			true,
			false,
			"error during Duo preAuth: denied",
		},
		{
			"PreAuth allowed but MFA required - failure",
			true,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			true,
			false,
			authApi.ErrMFARequired.Error(),
		},
		{
			"PreAuth allowed with MFA not required - success",
			false,
			passcode,
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			true,
			false,
			"",
		},
		{
			"PreAuth auth without MFA - failure",
			true,
			"",
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_no_push_devices.json",
				},
			},
			true,
			false,
			authApi.ErrMFAUnavailable.Error(),
		},
	}
	commonAuthTest(authTests, t)
}

func TestDuoAuthPushMFA(t *testing.T) {
	authTests := []authTest{
		{
			"Auth with push missing status - failure",
			true,
			"",
			[]authRequest{
				{
					"/auth/v2/check",
					"GET",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusOK,
					"check_success.json",
				},
				{
					"/auth/v2/preauth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{"username": url.QueryEscape(username)},
					http.StatusOK,
					"preauth_1_push_device.json",
				},
				{
					"/auth/v2/auth",
					"POST",
					map[string]string{"Date": ""},
					map[string]string{},
					http.StatusBadRequest,
					"empty.json",
				},
			},
			true,
			false,
			authApi.ErrPushFailed.Error(),
		},
	}
	commonAuthTest(authTests, t)
}
