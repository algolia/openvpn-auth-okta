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
	"gopkg.in/ini.v1"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
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
func (validator *OktaOpenVPNValidator) readConfigFile() error {
	var cfgPaths []string
	if validator.configFile == "" {
		for _, v := range cfgDefaultPaths {
			cfgPaths = append(cfgPaths, v)
		}
	} else {
		cfgPaths = append(cfgPaths, validator.configFile)
	}
	for _, cfgFile := range cfgPaths {
		if info, err := os.Stat(cfgFile); err != nil {
			continue
		} else {
			if info.IsDir() {
				continue
			} else {
				// should never fail as err would be not nil only if cfgFile is not a string (or a []byte, a Reader)
				cfg, err := ini.Load(cfgFile)
				if err != nil {
					log.Errorf("Error loading ini file \"%s\": %s",
						cfgFile,
						err)
					return err
				}
				apiConfig := validator.api.ApiConfig
				if err := cfg.Section("OktaAPI").StrictMapTo(apiConfig); err != nil {
					log.Errorf("Error parsing ini file \"%s\": %s",
						cfgFile,
						err)
					return err
				}
				if apiConfig.Url == "" || apiConfig.Token == "" {
					log.Errorf("Missing Url or Token parameter in \"%s\"",
						cfgFile)
					return errors.New("Missing param Url or Token")
				}
				validator.configFile = cfgFile
				return nil
			}
		}
	}
	log.Errorf("No ini file found in %v", cfgPaths)
	return errors.New("No ini file found")
}

// Read all allowed pubkey fingerprints for the API server from pinset file
func (validator *OktaOpenVPNValidator) loadPinset() error {
	var pinsetPaths []string
	if validator.pinsetFile == "" {
		for _, v := range pinsetDefaultPaths {
			pinsetPaths = append(pinsetPaths, v)
		}
	} else {
		pinsetPaths = append(pinsetPaths, validator.pinsetFile)
	}
	for _, pinsetFile := range pinsetPaths {
		if info, err := os.Stat(pinsetFile); err != nil {
			continue
		} else {
			if info.IsDir() {
				continue
			} else {
				if pinset, err := os.ReadFile(pinsetFile); err != nil {
					log.Errorf("Can not read pinset config file \"%s\": %s",
						pinsetFile,
						err)
					return err
				} else {
					pinsetArray := strings.Split(string(pinset), "\n")
					cleanPinset := removeComments(removeEmptyStrings(pinsetArray))
					validator.api.ApiConfig.AssertPin = cleanPinset
					validator.pinsetFile = pinsetFile
					return nil
				}
			}
		}
	}
	return errors.New("No pinset file found")
}
