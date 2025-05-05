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
	"errors"

	"gopkg.in/ini.v1"

	"github.com/phuslu/log"
)

func (auth *OktaAuthApi) ParseConfig(cfg *ini.File) error {
	auth.ProviderConfig = &ProviderApiConfig{
		Token:               "",
		MFAPushMaxRetries:   20,
		MFAPushDelaySeconds: 3,
		AllowedGroups:       "",
	}
	if err := cfg.Section("OktaAPI").StrictMapTo(auth.ProviderConfig); err != nil {
		log.Error().Msgf("Error parsing Okta scetion in ini file: %s",
			err)
		return err
	}
	if auth.ProviderConfig.Token == "" {
		log.Error().Msg("Missing Okta Token parameter")
		return errors.New("Missing param Okta Token")
	}
	return nil
}
