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
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
)

func TestDuoParseUrl(t *testing.T) {
	urlTests := map[string]string{
		"toto":                 "toto",
		"toto.com":             "toto.com",
		"https://toto.com":     "toto.com",
		"toto.com:443":         "toto.com:443",
		"https://toto.com:443": "toto.com:443",
	}
	apiCfg := &authApi.APIConfig{}
	a := &DuoAuthApi{ApiConfig: apiCfg}
	for test, expected := range urlTests {
		t.Run(fmt.Sprintf("parseUrl(%s)", test), func(t *testing.T) {
			apiCfg.Url = test
			assert.Equal(t, expected, a.parseUrl())
		})
	}
}
