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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
)

// used in TestReadConfigFile, TestLoadPinset
type testCfgFile struct {
	testName string
	path     string
	link     string
	errMsg   string
}

func TestParsePassword(t *testing.T) {
	t.Run("Parse password with passcode", func(t *testing.T) {
		setEnv(setupEnv)
		v := New()
		_ = v.loadEnvVars(nil)
		v.api.UserConfig.Password = "password123456"
		unsetEnv(setupEnv)
		v.parsePassword()
		assert.Equal(t, "password", v.api.UserConfig.Password)
		assert.Equal(t, "123456", v.api.UserConfig.Passcode)
	})
}

func TestReadConfigFile(t *testing.T) {
	tests := []testCfgFile{
		{
			"Valid config file - success",
			"../../testing/fixtures/validator/valid.ini",
			"",
			"",
		},
		{
			"Valid config file link - success",
			"",
			"../../testing/fixtures/validator/valid.ini",
			"",
		},
		{
			"Invalid config file - failure",
			"../../testing/fixtures/validator/invalid.ini",
			"",
			"Missing param Url or Token",
		},
		{
			"Invalid 2 config file - failure",
			"../../testing/fixtures/validator/invalid2.ini",
			"",
			"key-value delimiter not found: UsernameSuffix\n",
		},
		{
			"Missing config file - failure",
			"MISSING",
			"",
			"No ini file found",
		},
		{
			"Config file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			"No ini file found",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := New()
			v.configFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "api.ini")
			}
			err := v.readConfigFile()
			if test.path == "" {
				_ = os.Remove("api.ini")
			}
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

func TestLoadPinset(t *testing.T) {
	tests := []testCfgFile{
		{
			"Valid pinset file - success",
			"../../testing/fixtures/validator/valid.cfg",
			"",
			"",
		},
		{
			"Valid pinset link - success",
			"",
			"../../testing/fixtures/validator/valid.cfg",
			"",
		},
		{
			"Missing pinset file - failure",
			"MISSING",
			"",
			"No pinset file found",
		},
		{
			"Pinset file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			"No pinset file found",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := New()
			v.api = oktaApiAuth.New()
			v.pinsetFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "pinset.cfg")
			}
			err := v.loadPinset()
			if test.path == "" {
				_ = os.Remove("pinset.cfg")
			}
			if test.errMsg == "" {
				assert.NoError(t, err)
				assert.True(t, slices.Contains(v.api.ApiConfig.AssertPin, pin))
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}
