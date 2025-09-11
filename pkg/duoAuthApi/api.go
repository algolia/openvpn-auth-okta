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
	"time"

	duo "github.com/duosecurity/duo_api_golang"
	duoauth "github.com/duosecurity/duo_api_golang/authapi"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
)

// Prepare an http client with a safe TLS config
// validate the server public key against our list of pinned key fingerprint
func (auth *DuoAuthApi) Setup() error {
	if pool, err := authApi.ApiInitPool(auth.ApiConfig); err != nil {
		return err
	} else {
		auth.pool = pool
		api := duo.NewDuoApi(auth.ProviderConfig.Ikey,
			auth.ProviderConfig.Skey,
			auth.ApiConfig.Url,
			"Algolia Bastion",
			duo.SetTimeout(time.Duration(auth.ProviderConfig.Timeout)*time.Second))

		auth.duoApi = duoauth.NewAuthApi(*api)
		auth.duoApi.SetCustomHTTPClient(pool)
		return nil
	}
}

// only used by validator_test.go
// nolint:unused
/*
func (auth *DuoAuthApi) getPool() *http.Client {
	return auth.pool
}
*/
