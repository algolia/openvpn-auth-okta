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
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/oktaAuthApi"
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
		v.api = &OktaAuthApi{
			ApiConfig: &authApi.APIConfig{
				Provider:            "",
				AllowUntrustedUsers: false,
				MFARequired:         false,
				TOTPFallbackToPush:  false,
			},
			UserConfig: &authApi.APIUserConfig{},
		}
		_ = v.loadEnvVars(nil)
		userCfg := v.api.GetUserConfig()
		userCfg.Password = "password123456"
		unsetEnv(setupEnv)
		v.parsePassword()
		assert.Equal(t, "password", userCfg.Password)
		assert.Equal(t, "123456", userCfg.Passcode)
	})
}

func TestReadConfigFile(t *testing.T) {
	tests := []testCfgFile{
		{
			"Valid config file - success",
			"../../testing/fixtures/validator/valid-okta.ini",
			"",
			"",
		},
		{
			"Valid config file link - success",
			"",
			"../../testing/fixtures/validator/valid-okta.ini",
			"",
		},
		{
			"Invalid config file - failure",
			"../../testing/fixtures/validator/invalid.ini",
			"",
			"Unsupported MFA provider",
		},
		{
			"Invalid config file - missing url - failure",
			"../../testing/fixtures/validator/invalid4.ini",
			"",
			"Missing param Url",
		},
		{
			"Invalid config file - missing Okta token - failure",
			"../../testing/fixtures/validator/invalid5.ini",
			"",
			"Missing param Okta Token",
		},
		{
			"Invalid config file - invalid general config type - failure",
			"../../testing/fixtures/validator/invalid6.ini",
			"",
			"set field \"MFARequired\": parsing \"aaaaa\": invalid syntax",
		},
		{
			"Invalid config file - invalid Okta config type - failure",
			"../../testing/fixtures/validator/invalid7.ini",
			"",
			"set field \"MFAPushDelaySeconds\": strconv.ParseInt: parsing \"toto\": invalid syntax",
		},
		{
			"Invalid config file - invalid Duo config type - failure",
			"../../testing/fixtures/validator/invalid8.ini",
			"",
			"set field \"Timeout\": strconv.ParseInt: parsing \"aaaa\": invalid syntax",
		},
		{
			"Invalid config file - missing Duo param - failure",
			"../../testing/fixtures/validator/invalid9.ini",
			"",
			"Missing param iKey or sKey",
		},
		{
			"Invalid config file - missing delimiter - failure",
			"../../testing/fixtures/validator/invalid2.ini",
			"",
			"key-value delimiter not found: UsernameSuffix\n",
		},
		{
			"Invalid config file - invalid provider - failure",
			"../../testing/fixtures/validator/invalid3.ini",
			"",
			"Unsupported MFA provider",
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
			v.api = oktaAuthApi.New()
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
				assert.True(t, slices.Contains(v.api.GetApiConfig().AssertPin, pin))
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}
