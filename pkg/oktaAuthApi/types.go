// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaAuthApi

import (
	"net/http"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/authApi"
)

type ProviderApiConfig struct {
	// Your (company's) Okta API token
	Token string

	// Number of retries when waiting for MFA result
	MFAPushMaxRetries int // default: 20

	// Number of seconds to wait between MFA result retrieval tries
	MFAPushDelaySeconds int // default: 3

	// List (comma separated) of groups allowed to connect
	AllowedGroups string
}

type OktaAuthApi struct {
	ApiConfig      *authApi.APIConfig
	ProviderConfig *ProviderApiConfig
	UserConfig     *authApi.APIUserConfig
	pool           *http.Client
}
