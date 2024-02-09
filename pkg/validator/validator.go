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

	log "github.com/sirupsen/logrus"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
)

type OktaApiAuth = oktaApiAuth.OktaApiAuth

type OktaOpenVPNValidator struct {
	configFile      string
	pinsetFile      string
	usernameTrusted bool
	isUserValid     bool
	controlFile     string
	api             *OktaApiAuth
}

func NewOktaOpenVPNValidator() *OktaOpenVPNValidator {
	api := oktaApiAuth.NewOktaApiAuth()
	return &OktaOpenVPNValidator{
		usernameTrusted: false,
		isUserValid:     false,
		controlFile:     "",
		configFile:      "",
		api:             api,
	}
}

// Setup the validator depending on the way it's invoked
func (validator *OktaOpenVPNValidator) Setup(deferred bool, debug bool, args []string, pluginEnv *PluginEnv) bool {
	setLogFormatter(debug, "")
	if err := validator.readConfigFile(); err != nil {
		log.Error("ReadConfigFile failure")
		if deferred {
			/*
			 * if invoked as a deferred plugin, we should always exit 0 and write result
			 * in the control file.
			 * here the validator control may not have been yet set, force it
			 */
			validator.controlFile = os.Getenv("auth_control_file")
			validator.WriteControlFile()
		}
		return false
	}

	if !deferred {
		// We're running in "Script Plugins" mode with "via-env" method
		// see "--auth-user-pass-verify cmd method" in
		//   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
		if len(args) > 0 {
			// via-file" method
			if err := validator.loadViaFile(args[0]); err != nil {
				log.Error("LoadViaFile failure")
				return false
			}
		} else {
			// "via-env" method
			if err := validator.loadEnvVars(nil); err != nil {
				log.Error("LoadEnvVars failure")
				return false
			}
		}
	} else {
		// We're running in "Shared Object Plugin" mode
		// see https://openvpn.net/community-resources/using-alternative-authentication-methods/
		if err := validator.loadEnvVars(pluginEnv); err != nil {
			log.Error("LoadEnvVars (deferred) failure")
			validator.WriteControlFile()
			return false
		}
	}

	if err := validator.loadPinset(); err != nil {
		log.Error("LoadPinset failure")
		if deferred {
			validator.WriteControlFile()
		}
		return false
	}
	validator.parsePassword()
	if err := validator.api.InitPool(); err != nil {
		log.Error("Initpool failure")
		return false
	}
	setLogFormatter(debug, validator.api.UserConfig.Username)
	return true
}

// Authenticate the user against Okta API
func (validator *OktaOpenVPNValidator) Authenticate() error {
	if !validator.usernameTrusted {
		log.Warningf("is not trusted - failing")
		return errors.New("User not trusted")
	}
	if err := validator.api.Auth(); err == nil {
		validator.isUserValid = true
		return nil
	} else {
		return errors.New("Authentication failed")
	}
}

// Write the authentication result in the OpenVPN control file (only used in deferred mode)
func (validator *OktaOpenVPNValidator) WriteControlFile() {
	if err := validator.checkControlFilePerm(); err != nil {
		return
	}

	valToWrite := []byte("0")
	if validator.isUserValid {
		valToWrite = []byte("1")
	}
	if err := os.WriteFile(validator.controlFile, valToWrite, 0600); err != nil {
		log.Errorf("Failed to write to OpenVPN control file \"%s\": %s",
			validator.controlFile,
			err)
	}
}
