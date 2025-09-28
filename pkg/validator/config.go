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
	"errors"
	"os"
	"strings"

	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
	"gopkg.in/ini.v1"

	"github.com/phuslu/log"
)

var (
	cfgDefaultPaths = [5]string{
		"/etc/okta-auth-validator/api.ini",
		"/etc/openvpn/okta_openvpn.ini",
		"/etc/okta_openvpn.ini",
		"api.ini",
		"okta_openvpn.ini",
	}
	pinsetDefaultPaths = [5]string{
		"/etc/okta-auth-validator/pinset.cfg",
		"/etc/openvpn/okta_pinset.cfg",
		"/etc/okta_pinset.cfg",
		"pinset.cfg",
		"okta_pinset.cfg",
	}
)

// Read the ini file containing the API config
func (validator *OpenVPNValidator) readConfigFile() error {
	log.Trace().Msg("validator.readConfigFile()")
	var cfgPaths []string
	if validator.configFile == "" {
		for _, v := range cfgDefaultPaths {
			cfgPaths = append(cfgPaths, v)
		}
	} else {
		cfgPaths = append(cfgPaths, validator.configFile)
	}

	for _, cfgFile := range cfgPaths {
		info, err := os.Stat(cfgFile)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		// should never fail as err would be not nil only if cfgFile is not a string (or a []byte, a Reader)
		cfg, err := ini.Load(cfgFile)
		if err != nil {
			log.Error().Msgf("Error loading ini file \"%s\": %s",
				cfgFile,
				err)
			return err
		}

		log.DefaultLogger.Level = log.ParseLevel(
			cfg.Section("General").Key("LogLevel").In(
				log.DefaultLogger.Level.String(),
				[]string{"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR"}))

		apiConfig := &authApi.APIConfig{
			Provider:            "",
			AllowUntrustedUsers: false,
			MFARequired:         false,
			TOTPFallbackToPush:  false,
		}

		// Identify the MFA provider from the "General" section
		apiConfig.Provider = cfg.Section("General").Key("Provider").In(
			"",
			[]string{"Okta", "Duo"})

		if apiConfig.Provider != "Duo" && apiConfig.Provider != "Okta" {
			log.Error().Msgf("Unsupported MFA provider %s in \"%s\"",
				apiConfig.Provider,
				cfgFile)
			return errors.New("Unsupported MFA provider")
		}

		switch apiConfig.Provider {
		case "Okta":
			validator.api = &OktaAuthApi{
				ApiConfig:  apiConfig,
				UserConfig: &authApi.APIUserConfig{},
			}

		case "Duo":
			validator.api = &DuoAuthApi{
				ApiConfig:  apiConfig,
				UserConfig: &authApi.APIUserConfig{},
			}
		}

		if err = validator.api.ParseConfig(cfg); err != nil {
			return err
		}

		if err := cfg.Section("General").StrictMapTo(apiConfig); err != nil {
			log.Error().Msgf("Error parsing ini file \"%s\": %s",
				cfgFile,
				err)
			return err
		}

		if apiConfig.Url == "" {
			log.Error().Msgf("Missing Url parameter in \"%s\"",
				cfgFile)
			return errors.New("Missing param Url")
		}

		validator.configFile = cfgFile
		return nil
	}
	log.Error().Msgf("No ini file found in %v", cfgPaths)
	return errors.New("No ini file found")
}

// Read all allowed pubkey fingerprints for the API server from pinset file
func (validator *OpenVPNValidator) loadPinset() error {
	log.Trace().Msg("validator.loadPinset()")
	var pinsetPaths []string
	if validator.pinsetFile == "" {
		for _, v := range pinsetDefaultPaths {
			pinsetPaths = append(pinsetPaths, v)
		}
	} else {
		pinsetPaths = append(pinsetPaths, validator.pinsetFile)
	}

	for _, pinsetFile := range pinsetPaths {
		info, err := os.Stat(pinsetFile)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		pinset, err := os.ReadFile(pinsetFile)
		if err != nil {
			log.Error().Msgf("Can not read pinset config file \"%s\": %s",
				pinsetFile,
				err)
			return err
		}

		pinsetArray := strings.Split(string(pinset), "\n")
		cleanPinset := removeComments(removeEmptyStrings(pinsetArray))
		validator.api.GetApiConfig().AssertPin = cleanPinset
		validator.pinsetFile = pinsetFile
		return nil
	}
	return errors.New("No pinset file found")
}
