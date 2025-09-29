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
	"time"

	duo "github.com/duosecurity/duo_api_golang"
	duoauth "github.com/duosecurity/duo_api_golang/authapi"
	"github.com/phuslu/log"
)

func (auth *DuoAuthApi) parseUrl() string {
	if duoHost, err := url.Parse(auth.ApiConfig.Url); err == nil {
		if duoHost.Port() != "" {
			return fmt.Sprintf("%s:%s", duoHost.Hostname(), duoHost.Port())
		}
		if duoHost.Hostname() != "" {
			return duoHost.Hostname()
		}
	}
	return auth.ApiConfig.Url
}

// Prepare an http client with a safe TLS config
// validate the server public key against our list of pinned key fingerprint
func (auth *DuoAuthApi) Setup() (err error) {
	log.Trace().Msg("duoAuthApi.Setup()")
	var pool *http.Client
	if pool, err = auth.ApiConfig.ApiInitPool(); err != nil {
		return err
	}
	auth.pool = pool
	api := duo.NewDuoApi(auth.ProviderConfig.Ikey,
		auth.ProviderConfig.Skey,
		auth.parseUrl(),
		"Algolia Bastion",
		duo.SetTimeout(time.Duration(auth.ProviderConfig.Timeout)*time.Second))

	auth.duoApi = duoauth.NewAuthApi(*api)
	auth.duoApi.SetCustomHTTPClient(pool)
	return nil
}

// only used by validator_test.go
// nolint:unused
func (auth *DuoAuthApi) getPool() *http.Client {
	return auth.pool
}
