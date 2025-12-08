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

// PluginEnv encapsulates OpenVPN environment variables passed to the validator
// when running in deferred plugin mode (Shared Object Plugin).
//
// In deferred mode, OpenVPN loads the plugin as a shared library and invokes it
// with environment variables containing connection details. The C plugin layer
// extracts these variables and marshals them into this struct before passing to Go.
//
// Security note: These values come from OpenVPN's plugin API and are considered
// trusted. The Username from environment is only trusted if it matches CommonName
// from the client's SSL certificate (controlled by AllowUntrustedUsers config).
type PluginEnv struct {
	// ControlFile is the absolute path to the OpenVPN auth control file.
	// The validator writes "1" (success) or "0" (failure) to this file.
	// OpenVPN reads this file to determine authentication result.
	// Example: "/tmp/openvpn_acf_abc123.tmp"
	ControlFile string

	// ClientIp is the untrusted IP address of the OpenVPN client.
	// Forwarded to Okta API as X-Forwarded-For for audit/security purposes.
	// Example: "192.168.1.100"
	ClientIp string

	// CommonName is the CN field from the client's SSL certificate.
	// Used as the trusted username source when AllowUntrustedUsers is false.
	// Example: "user@example.com" or "john.doe"
	CommonName string

	// Username is the username submitted by the client during authentication.
	// Only trusted if AllowUntrustedUsers is true or matches CommonName.
	// Example: "john.doe"
	Username string

	// Password is the password submitted by the client.
	// May contain appended TOTP passcode (last 6 digits).
	// Example: "mypassword123456" (password + TOTP)
	Password string
}

// loadViaFile reads user credentials from a temporary file (via-file method).
//
// In script plugin mode with via-file method, OpenVPN writes credentials to a
// temporary file and passes the path as an argument. This is more secure than
// via-env on systems where environment variables might be visible to other users.
//
// File format (created by OpenVPN):
//	Line 1: username
//	Line 2: password (may include appended TOTP)
//
// Security considerations:
//  - File should be on tmpfs to prevent credentials touching disk
//  - OpenVPN creates file with restrictive permissions
//  - File is deleted by OpenVPN after plugin completes
//
// The function:
//  1. Validates file exists and is readable
//  2. Reads and parses the two-line format
//  3. Validates username format per OpenVPN requirements
//  4. Applies UsernameSuffix if configured
//  5. Sets usernameTrusted=true (via-file implies SSL cert auth)
//
// Parameters:
//   - path: absolute path to temporary credentials file
//
// Returns nil on success, error if file invalid or credentials malformed.
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
		return errors.New("invalid via-file")
	}
	username := viaFileInfos[0]
	password := viaFileInfos[1]

	if !checkUsernameFormat(username) {
		log.Error().Msg("Username or CN invalid format")
		return errors.New("invalid CN or username format")
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

// loadEnvVars extracts user credentials and metadata from OpenVPN environment variables.
//
// This function handles both script plugin mode (via-env) and deferred plugin mode.
// The source of environment variables differs by mode:
//  - Script mode: Standard Unix environment variables set by OpenVPN
//  - Deferred mode: Passed via pluginEnv struct marshalled from C plugin
//
// Environment variables used:
//  - username: User-submitted username (untrusted unless cert validated)
//  - password: User-submitted password (may include appended TOTP)
//  - common_name: CN from client SSL certificate (trusted identity source)
//  - untrusted_ip: Client IP address (forwarded to Okta for audit)
//  - auth_control_file: Path to write authentication result (deferred mode only)
//
// Username trust model:
//  - If AllowUntrustedUsers=false: username must match common_name (SSL cert)
//  - If AllowUntrustedUsers=true: username from credentials is trusted (NOT RECOMMENDED)
//
// The function:
//  1. Populates pluginEnv from environment if nil (script mode)
//  2. Validates control file is present (deferred mode warning if missing)
//  3. Determines username trust based on SSL certificate and config
//  4. Validates username and password are present and properly formatted
//  5. Applies UsernameSuffix if configured and username lacks @
//  6. Sets client IP for Okta API X-Forwarded-For header
//
// Parameters:
//   - pluginEnv: pre-populated environment (deferred mode) or nil (script mode)
//
// Returns nil on success, error if credentials missing or invalid.
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
		return errors.New("no CN or username")
	}

	if pluginEnv.Password == "" {
		log.Error().Msg("No password provided")
		return errors.New("no password")
	}

	if !checkUsernameFormat(pluginEnv.Username) {
		log.Error().Msg("Username or CN invalid format")
		return errors.New("invalid CN or username format")
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
