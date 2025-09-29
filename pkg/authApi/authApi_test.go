// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package authApi

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/OAtest"
)

type poolTest struct {
	testName string
	host     string
	port     string
	pinset   []string
	errMsg   string
}

type errorTest struct {
	testName    string
	inputErrMsg string
	inputErr2   error
	count       int
	errMsg      string
}

func TestApiInitPool(t *testing.T) {
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
			a := &APIConfig{
				Url:       fmt.Sprintf("https://%s:%s", test.host, test.port),
				AssertPin: test.pinset,
			}
			h, err := a.ApiInitPool()
			if test.errMsg == "" {
				assert.NoError(t, err)
				assert.NotNil(t, h)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
					assert.Nil(t, h)
				}
			}
		})
	}
	if err := srv.Close(); err != nil {
		panic(err) // failure/timeout shutting down the server gracefully
	}
}

func TestApiParseError(t *testing.T) {
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
			err := ParseError(inputErr, test.count, 2)
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
