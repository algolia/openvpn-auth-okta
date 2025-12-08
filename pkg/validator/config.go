// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*
Configuration Options:

[General]
LogLevel: Sets the verbosity level (TRACE, DEBUG, INFO, WARN, ERROR)
Default: INFO

[OktaAPI]
Url: The base URL for your Okta instance
Required: true

Token: API token for Okta authentication
Required: true

UsernameSuffix: Suffix to append to usernames (e.g., "@company.com")
Default: ""

AllowUntrustedUsers: Allow authentication without client certificates
Warning: Not recommended for production
Default: false

AllowedGroups: Comma-separated list of group names that can connect
Default: ""

MFARequired: Require MFA for all users
Default: false

MFAPushMaxRetries: Maximum retries for PUSH MFA
Default: 20

MFAPushDelaySeconds: Delay between PUSH MFA retries (seconds)
Default: 3

TOTPFallbackToPush: If TOTP fails, try PUSH MFA
Default: false

PasscodeSeparator: Character separating password from TOTP code
Default: ""
*/

package validator

import (
	"errors"
	"os"
	"strings"

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

// readConfigFile locates and loads the api.ini configuration file.
//
// The function searches for configuration files in the following order:
//  1. /etc/okta-auth-validator/api.ini (recommended location)
//  2. /etc/openvpn/okta_openvpn.ini (legacy location)
//  3. /etc/okta_openvpn.ini (legacy location)
//  4. ./api.ini (current directory)
//  5. ./okta_openvpn.ini (current directory)
//
// If validator.configFile is already set, only that path is checked.
//
// Configuration validation:
//  - Url and Token are required fields (must not be empty)
//  - PasscodeSeparator must be empty or exactly 1 character
//  - LogLevel is validated and applied to the logger
//
// The function uses strict mapping to ensure all INI keys are valid,
// preventing silent configuration errors.
//
// Returns nil on success, error if no valid config found or validation fails.
func (validator *OktaOpenVPNValidator) readConfigFile() error {
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

		apiConfig := validator.api.ApiConfig
		if err := cfg.Section("OktaAPI").StrictMapTo(apiConfig); err != nil {
			log.Error().Msgf("Error parsing ini file \"%s\": %s",
				cfgFile,
				err)
			return err
		}
		if apiConfig.Url == "" || apiConfig.Token == "" {
			log.Error().Msgf("Missing Url or Token parameter in \"%s\"",
				cfgFile)
			return errors.New("missing param Url or Token")
		}
		if len(apiConfig.PasscodeSeparator) > 1 {
			log.Error().Msgf("Invalid passcode separator in \"%s\", it should be empty or 1 character long",
				cfgFile)
			return errors.New("invalid passcode separator")
		}
		validator.configFile = cfgFile
		return nil
	}
	log.Error().Msgf("No ini file found in %v", cfgPaths)
	return errors.New("no ini file found")
}

// loadPinset reads TLS certificate public key fingerprints for Okta API validation.
//
// TLS certificate pinning is a critical security feature that prevents man-in-the-middle
// attacks. The pinset.cfg file contains base64-encoded SHA256 digests of Okta's public
// keys. During InitPool(), the validator verifies Okta's certificate matches one of
// these fingerprints before accepting the connection.
//
// The function searches for pinset files in the following order:
//  1. /etc/okta-auth-validator/pinset.cfg (recommended location)
//  2. /etc/openvpn/okta_pinset.cfg (legacy location)
//  3. /etc/okta_pinset.cfg (legacy location)
//  4. ./pinset.cfg (current directory)
//  5. ./okta_pinset.cfg (current directory)
//
// If validator.pinsetFile is already set, only that path is checked.
//
// File format:
//  - One base64-encoded SHA256 digest per line
//  - Lines starting with # are comments (ignored)
//  - Empty lines are ignored
//
// Returns nil on success, error if no pinset file found.
//
// Security note: This file must be updated when Okta rotates their TLS certificates.
func (validator *OktaOpenVPNValidator) loadPinset() error {
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
		validator.api.ApiConfig.AssertPin = cleanPinset
		validator.pinsetFile = pinsetFile
		return nil
	}
	return errors.New("no pinset file found")
}
