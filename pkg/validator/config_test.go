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
	"fmt"
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
	err      error
}

func TestParsePassword(t *testing.T) {
	t.Run("Parse password with passcode", func(t *testing.T) {
		setEnv(setupEnv)
		v := NewOktaOpenVPNValidator()
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
			nil,
		},
		{
			"Valid config file link - success",
			"",
			"../../testing/fixtures/validator/valid.ini",
			nil,
		},
		{
			"Invalid config file - failure",
			"../../testing/fixtures/validator/invalid.ini",
			"",
			fmt.Errorf("Missing param Url or Token"),
		},
		{
			"Invalid 2 config file - failure",
			"../../testing/fixtures/validator/invalid2.ini",
			"",
			fmt.Errorf("key-value delimiter not found: UsernameSuffix\n"),
		},
		{
			"Missing config file - failure",
			"MISSING",
			"",
			fmt.Errorf("No ini file found"),
		},
		{
			"Config file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			fmt.Errorf("No ini file found"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.configFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "api.ini")
			}
			err := v.readConfigFile()
			if test.path == "" {
				_ = os.Remove("api.ini")
			}
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
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
			nil,
		},
		{
			"Valid pinset link - success",
			"",
			"../../testing/fixtures/validator/valid.cfg",
			nil,
		},
		{
			"Missing pinset file - failure",
			"MISSING",
			"",
			fmt.Errorf("No pinset file found"),
		},
		{
			"Pinset file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			fmt.Errorf("No pinset file found"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.api = oktaApiAuth.NewOktaApiAuth()
			v.pinsetFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "pinset.cfg")
			}
			err := v.loadPinset()
			if test.path == "" {
				_ = os.Remove("pinset.cfg")
			}
			if test.err == nil {
				assert.Nil(t, err)
				assert.True(t, slices.Contains(v.api.ApiConfig.AssertPin, pin))
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
