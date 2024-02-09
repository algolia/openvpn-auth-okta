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

import "net/http"

const userAgent string = "Mozilla/5.0 (Linux; x86_64) OktaOpenVPN/2.1.0"

// Contains the configuration for the Okta API connection
// Those configuration options are read from api.ini
type OktaAPIConfig struct {
	// Okta API server url, ie https://example.oktapreview.com
	Url string

	// Your (company's) Okta API token
	Token string

	// The suffix to be added to your users names:
	// ie if UsernameSuffix = "example.com" and your user logs in with "dade.murphy"
	// the validator will try to authenticate for "dade.murphy@example.com"
	UsernameSuffix string

	// A list of valid SSL public key fingerprint to validate the Okta API server certificate against
	AssertPin []string

	// Is MFA Required for all users. If yes and Okta authenticates the user without MFA (not configured)
	// the validator will reject it.
	MFARequired bool // default: false

	// Do not require usernames to come from client-side SSL certificates
	AllowUntrustedUsers bool // default: false

	// Number of retries when waiting for MFA result
	MFAPushMaxRetries int // default = 20

	// Number of seconds to wait between MFA result retrieval tries
	MFAPushDelaySeconds int // default = 3

	// List (comma separated) of groups allowed to connect
	AllowedGroups string
}

// User credentials and informations
type OktaUserConfig struct {
	Username string
	Password string
	Passcode string
	ClientIp string
}

type OktaApiAuth struct {
	ApiConfig  *OktaAPIConfig
	UserConfig *OktaUserConfig
	pool       *http.Client
	userAgent  string
}
