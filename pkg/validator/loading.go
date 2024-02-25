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
	"fmt"
	"os"
	"strings"

	"github.com/phuslu/log"
)

// PluginEnv represents the information passed to the validator when it's running as
// `Shared Object Plugin`
type PluginEnv struct {
	// ControlFile is the path to the OpenVPN auth control file
	// where the authentication result is written
	ControlFile string

	// The OpenVPN client ip address, used as `X-Forwarded-For` payload attribute
	// to the Okta API
	ClientIp string

	// The CN of the SSL certificate presented by the OpenVPN client
	CommonName string

	// The client username submitted during OpenVPN authentication
	Username string

	// The client password submitted during OpenVPN authentication
	Password string
}

// Get user credentials from the OpenVPN via-file
func (validator *OktaOpenVPNValidator) loadViaFile(path string) error {
	log.Trace().Msg("validator.loadViaFile()")
	if _, err := os.Stat(path); err != nil {
		log.Error().Msgf("OpenVPN via-file \"%s\" does not exists", path)
		return err
	}

	viaFileBuf, err := os.ReadFile(path)
	if err != nil {
		log.Error().Msgf("Can not read OpenVPN via-file \"%s\": %s",
			path,
			err)
		return err
	}

	viaFileInfos := strings.Split(string(viaFileBuf), "\n")
	viaFileInfos = removeEmptyStrings(viaFileInfos)
	if len(viaFileInfos) < 2 {
		log.Error().Msgf("Invalid OpenVPN via-file \"%s\" content", path)
		return errors.New("Invalid via-file")
	}
	username := viaFileInfos[0]
	password := viaFileInfos[1]

	if !checkUsernameFormat(username) {
		log.Error().Msg("Username or CN invalid format")
		return errors.New("Invalid CN or username format")
	}

	apiConfig := validator.api.ApiConfig
	validator.usernameTrusted = true
	if apiConfig.UsernameSuffix != "" && !strings.Contains(username, "@") {
		username = fmt.Sprintf("%s@%s", username, apiConfig.UsernameSuffix)
	}
	userConfig := validator.api.UserConfig
	userConfig.Username = username
	userConfig.Password = password
	return nil
}

// Get user credentials and info from the environment set by OpenVPN
func (validator *OktaOpenVPNValidator) loadEnvVars(pluginEnv *PluginEnv) error {
	log.Trace().Msg("validator.loadEnvVars()")
	if pluginEnv == nil {
		pluginEnv = &PluginEnv{
			Username:   os.Getenv("username"),
			CommonName: os.Getenv("common_name"),
			Password:   os.Getenv("password"),
			// TODO: use the local public ip as fallback
			ClientIp:    getEnv("untrusted_ip", ""),
			ControlFile: os.Getenv("auth_control_file"),
		}
	}
	validator.controlFile = pluginEnv.ControlFile

	if validator.controlFile == "" {
		log.Warn().Msg("No control file found, if using a deferred plugin auth will stall and fail.")
	}
	// if the username comes from a certificate and AllowUntrustedUsers is false:
	// user is trusted
	// otherwise BE CAREFUL, username from OpenVPN credentials will be used !
	apiConfig := validator.api.ApiConfig
	if pluginEnv.CommonName != "" && !apiConfig.AllowUntrustedUsers {
		validator.usernameTrusted = true
		pluginEnv.Username = pluginEnv.CommonName
	}

	// if username is empty, there is an issue somewhere
	if pluginEnv.Username == "" {
		log.Error().Msg("No username or CN provided")
		return errors.New("No CN or username")
	}

	if pluginEnv.Password == "" {
		log.Error().Msg("No password provided")
		return errors.New("No password")
	}

	if !checkUsernameFormat(pluginEnv.Username) {
		log.Error().Msg("Username or CN invalid format")
		return errors.New("Invalid CN or username format")
	}

	if apiConfig.AllowUntrustedUsers {
		validator.usernameTrusted = true
	}
	if apiConfig.UsernameSuffix != "" && !strings.Contains(pluginEnv.Username, "@") {
		pluginEnv.Username = fmt.Sprintf("%s@%s", pluginEnv.Username, apiConfig.UsernameSuffix)
	}

	userConfig := validator.api.UserConfig
	userConfig.Username = pluginEnv.Username
	userConfig.Password = pluginEnv.Password
	userConfig.ClientIp = pluginEnv.ClientIp
	return nil
}
