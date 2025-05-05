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

const (
	// used in TestWriteControlFile
	controlFile  string = "../../testing/fixtures/validator/control_file"
	oktaEndpoint string = "https://example.oktapreview.com"
	token        string = "12345"
)

var setupEnv = map[string]string{
	"username":          "dade.murphy",
	"common_name":       "",
	"password":          "password",
	"untrusted_ip":      "1.2.3.4",
	"auth_control_file": controlFile,
}

type testWriteFile struct {
	testName  string
	userValid bool
	expected  string
}

type testSetup struct {
	testName   string
	cfgFile    string
	pinsetFile string
	deferred   bool
	env        map[string]string
	args       []string
	ret        bool
}

type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}

type testAuthenticate struct {
	testName    string
	cfgFile     string
	pinsetFile  string
	userTrusted bool
	requests    []authRequest
	ret         bool
	errMsg      string
}
