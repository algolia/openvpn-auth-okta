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
	"errors"

	"github.com/phuslu/log"
	"gopkg.in/ini.v1"
)

func (auth *DuoAuthApi) ParseConfig(cfg *ini.File) error {
	auth.ProviderConfig = &ProviderApiConfig{
		Ikey:    "",
		Skey:    "",
		Timeout: 30,
	}
	if err := cfg.Section("DuoAPI").StrictMapTo(auth.ProviderConfig); err != nil {
		log.Error().Msgf("Error parsing Okta scetion in ini file: %s",
			err)
		return err
	}
	if auth.ProviderConfig.Ikey == "" || auth.ProviderConfig.Skey == "" {
		log.Error().Msg("Missing Duo key parameter")
		return errors.New("Missing param iKey or sKey")
	}

	return nil
}
