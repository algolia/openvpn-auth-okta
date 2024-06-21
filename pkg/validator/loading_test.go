// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validator

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
)

const pin string = "SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="

type testViaFile struct {
	testName         string
	path             string
	usernameSuffix   string
	expectedUsername string
	expectedPassword string
	errMsg           string
}

type testEnvVar struct {
	testName            string
	usernameSuffix      string
	allowUntrustedUsers bool
	expectedTrusted     bool
	expectedUsername    string
	env                 map[string]string
	errMsg              string
}

func TestLoadViaFile(t *testing.T) {
	tests := []testViaFile{
		{
			"Valid via file with suffix - success",
			"../../testing/fixtures/validator/valid_viafile.cfg",
			"example.com",
			"dade.murphy@example.com",
			"password",
			"",
		},
		{
			"Valid via file without suffix - success",
			"../../testing/fixtures/validator/valid_viafile.cfg",
			"",
			"dade.murphy",
			"password",
			"",
		},
		{
			"Invalid via file - failure",
			"../../testing/fixtures/validator/invalid_viafile.cfg",
			"",
			"dade.murphy",
			"password",
			"Invalid via-file",
		},
		{
			"Invalid username in via file - failure",
			"../../testing/fixtures/validator/invalid_username_viafile.cfg",
			"",
			"dade.murphy*",
			"password",
			"Invalid CN or username format",
		},
		{
			"Missing via file - failure",
			"MISSING",
			"",
			"dade.murphy",
			"password",
			"stat MISSING: no such file or directory",
		},
		{
			"Via file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			"dade.murphy",
			"password",
			"read ../../testing/fixtures/validator/: is a directory",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := New()
			v.api = oktaApiAuth.New()
			v.api.ApiConfig.UsernameSuffix = test.usernameSuffix
			err := v.loadViaFile(test.path)
			if test.errMsg == "" {
				assert.NoError(t, err)
				assert.NotNil(t, v.api.UserConfig)
				assert.Equal(t, test.expectedUsername, v.api.UserConfig.Username)
				assert.Equal(t, test.expectedPassword, v.api.UserConfig.Password)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}

func setEnv(e map[string]string) {
	for k, v := range e {
		os.Setenv(k, v)
	}
}

func unsetEnv(e map[string]string) {
	for k := range e {
		os.Unsetenv(k)
	}
}

func TestLoadEnvVars(t *testing.T) {
	tests := []testEnvVar{
		{
			"Test username/allowUntrustedUsers/usernameSuffix - succes",
			"example.com",
			true,
			true,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"",
		},
		{
			"Test username/no password - failure",
			"example.com",
			true,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "",
				"untrusted_ip": "1.2.3.4",
			},
			"No password",
		},
		{
			"Test username/!allowUntrustedUsers/usernameSuffix - success",
			"example.com",
			false,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"",
		},
		{
			"Test common_name/!allowUntrustedUsers/usernameSuffix - success",
			"example.com",
			false,
			true,
			"dade.murphy2@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "dade.murphy2",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"",
		},
		{
			"Test username/common_name/allowUntrustedUsers/usernameSuffix - success",
			"example.com",
			true,
			true,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "dade.murphy2",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"",
		},
		{
			"Test empty username/common_name - failure",
			"example.com",
			false,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"No CN or username",
		},
		{
			"Test invalid username/common_name - failure",
			"example.com",
			false,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy*",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			"Invalid CN or username format",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			setEnv(test.env)
			v := New()
			v.api.ApiConfig.UsernameSuffix = test.usernameSuffix
			v.api.ApiConfig.AllowUntrustedUsers = test.allowUntrustedUsers
			err := v.loadEnvVars(nil)
			unsetEnv(test.env)
			assert.Equal(t, test.expectedTrusted, v.usernameTrusted)
			if test.errMsg == "" {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedUsername, v.api.UserConfig.Username)
			} else {
				assert.EqualError(t, err, test.errMsg)
			}
		})
	}
}
