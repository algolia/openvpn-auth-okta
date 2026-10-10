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
Package validator provides OpenVPN authentication against Okta.

The validator package implements the core authentication logic for OpenVPN
connections using Okta's Authentication API. It supports both deferred plugin mode
and script plugin mode.

Key Features:
- Multi-factor authentication (TOTP and PUSH)
- TLS certificate pinning
- Group-based access control
- Detailed logging and auditing
- Secure credential handling

The validator can be used in two modes:
1. Deferred mode (C plugin): Called by OpenVPN as a shared library
2. Script mode (binary): Called by OpenVPN as a command-line tool

Usage Example:
    // Create validator with INFO level logging
    v := validator.New("INFO")

    // Setup for deferred mode (C plugin)
    if !v.Setup(true, nil, pluginEnv) {
        // Handle setup failure
        return false
    }

    // Authenticate user
    err := v.Authenticate()
    if err != nil {
        // Handle authentication failure
        return false
    }

    // Write result to control file (deferred mode only)
    v.WriteControlFile()
*/

package validator

import (
	"errors"
	"os"
	"slices"

	"github.com/google/uuid"
	"github.com/phuslu/log"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
)

type OktaApiAuth = oktaApiAuth.OktaApiAuth

// OktaOpenVPNValidator orchestrates OpenVPN authentication against Okta's API.
// It manages the complete authentication lifecycle including configuration loading,
// credential validation, MFA verification, and result reporting.
//
// The validator supports two operational modes:
//   - Deferred mode: Runs as a shared library loaded by OpenVPN's plugin system
//   - Script mode: Runs as a standalone binary called by OpenVPN's auth-user-pass-verify
//
// Security considerations:
//   - Validates TLS certificates against pinned public keys (see pinset.cfg)
//   - Ensures credentials never touch disk in deferred mode
//   - Validates control file permissions to prevent unauthorized access
//   - Uses structured logging with session UUIDs for audit trails
type OktaOpenVPNValidator struct {
	configFile      string       // Path to api.ini configuration file
	pinsetFile      string       // Path to pinset.cfg for TLS pinning
	usernameTrusted bool         // True if username comes from client SSL certificate
	isUserValid     bool         // Authentication result (success/failure)
	controlFile     string       // Path to OpenVPN control file for deferred mode
	sessionId       string       // UUID for correlating log entries
	api             *OktaApiAuth // Okta API client instance
}

// New creates and initializes a new OktaOpenVPNValidator instance.
//
// The optional logLevel parameter sets the logging verbosity. If not provided or invalid,
// defaults to "INFO". Valid levels are: TRACE, DEBUG, INFO, WARN, WARNING, ERROR.
//
// Each validator instance is assigned a unique session UUID that appears in all log
// messages, enabling correlation of log entries for a single authentication attempt.
//
// Example:
//
//	v := validator.New()           // INFO level logging
//	v := validator.New("DEBUG")    // DEBUG level logging
//	v := validator.New("TRACE")    // TRACE level logging (very verbose)
//
// The validator must be configured via Setup() before calling Authenticate().
func New(args ...string) *OktaOpenVPNValidator {
	api := oktaApiAuth.New()
	luuid := uuid.NewString()
	defaultLevel := "INFO"
	if len(args) > 0 {
		if slices.Contains([]string{"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR"}, args[0]) {
			defaultLevel = args[0]
		}
	}
	v := &OktaOpenVPNValidator{
		usernameTrusted: false,
		isUserValid:     false,
		controlFile:     "",
		configFile:      "",
		sessionId:       luuid,
		api:             api,
	}
	v.initLogFormatter(log.ParseLevel(defaultLevel))
	return v
}

// Setup configures the validator based on the invocation mode and loads necessary credentials.
//
// Parameters:
//   - deferred: true for deferred plugin mode (shared library), false for script mode
//   - args: command-line arguments (used in script mode for via-file method)
//   - pluginEnv: environment variables from OpenVPN (used in deferred mode)
//
// In script mode (deferred=false):
//   - If args is empty: reads credentials from environment variables (via-env method)
//   - If args[0] provided: reads credentials from file at that path (via-file method)
//
// In deferred mode (deferred=true):
//   - Reads credentials from pluginEnv struct populated by C plugin
//   - On any error, writes failure to control file before returning
//
// The function performs these operations:
//  1. Loads and validates api.ini configuration
//  2. Extracts user credentials (username, password, client IP)
//  3. Loads TLS certificate pinset for Okta API
//  4. Parses TOTP passcode from password if present
//  5. Initializes HTTP client pool with TLS pinning
//
// Returns true on successful setup, false otherwise. Errors are logged.
//
// Security note: In deferred mode, this function writes to the control file on error
// to ensure OpenVPN receives a response (required for deferred plugin operation).
func (validator *OktaOpenVPNValidator) Setup(deferred bool, args []string, pluginEnv *PluginEnv) bool {
	log.Trace().Msg("validator.Setup()")
	if err := validator.readConfigFile(); err != nil {
		log.Error().Msg("ReadConfigFile failure")
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
				log.Error().Msg("LoadViaFile failure")
				return false
			}
		} else {
			// "via-env" method
			if err := validator.loadEnvVars(nil); err != nil {
				log.Error().Msg("LoadEnvVars failure")
				return false
			}
		}
	} else {
		// We're running in "Shared Object Plugin" mode
		// see https://openvpn.net/community-resources/using-alternative-authentication-methods/
		if err := validator.loadEnvVars(pluginEnv); err != nil {
			log.Error().Msg("LoadEnvVars (deferred) failure")
			validator.WriteControlFile()
			return false
		}
	}

	if err := validator.loadPinset(); err != nil {
		log.Error().Msg("LoadPinset failure")
		if deferred {
			validator.WriteControlFile()
		}
		return false
	}
	validator.parsePassword()
	if err := validator.api.InitPool(); err != nil {
		log.Error().Msg("Initpool failure")
		return false
	}
	validator.setLogUser()
	return true
}

// Authenticate performs the complete authentication flow against Okta's API.
//
// The authentication process includes:
//  1. Validates that the username is from a trusted source (SSL certificate)
//  2. Calls Okta pre-authentication endpoint to determine authentication requirements
//  3. Performs MFA verification if required (TOTP or Push)
//  4. Optionally validates user group membership if AllowedGroups is configured
//
// Setup() must be called successfully before calling this method.
//
// Returns nil on successful authentication, error otherwise. On success,
// sets validator.isUserValid to true which will be written to the control
// file by WriteControlFile() in deferred mode.
//
// Common error scenarios:
//   - User not trusted (username not from SSL certificate)
//   - Invalid Okta credentials
//   - MFA verification failed or timed out
//   - User not member of required groups
//   - Network/API errors communicating with Okta
//
// All authentication attempts are logged with the session UUID for auditing.
func (validator *OktaOpenVPNValidator) Authenticate() error {
	log.Trace().Msg("validator.Authenticate()")
	if !validator.usernameTrusted {
		log.Warn().Msgf("is not trusted - failing")
		return errors.New("user not trusted")
	}

	if err := validator.api.Auth(); err != nil {
		return errors.New("authentication failed")
	}

	validator.isUserValid = true
	return nil
}

// WriteControlFile writes the authentication result to OpenVPN's control file.
//
// This function is only used in deferred plugin mode. OpenVPN creates a control file
// whose path is provided via the auth_control_file environment variable. The plugin
// writes "1" for success or "0" for failure, then OpenVPN reads this file to determine
// whether to allow or deny the connection.
//
// Security validations performed:
//   - Verifies control file directory is not group/world writable (prevents race conditions)
//   - Sets file permissions to 0600 (owner read/write only)
//
// The function is safe to call multiple times and in error conditions. If the control
// file path is empty or invalid, the function logs an error and returns without panicking.
//
// Note: This function always succeeds from the caller's perspective (no return value).
// Errors are logged but do not propagate, as there's no recovery mechanism in deferred mode.
func (validator *OktaOpenVPNValidator) WriteControlFile() {
	log.Trace().Msg("validator.WriteControlFile()")
	if err := validator.checkControlFilePerm(); err != nil {
		return
	}

	valToWrite := []byte("0")
	if validator.isUserValid {
		valToWrite = []byte("1")
	}
	if err := os.WriteFile(validator.controlFile, valToWrite, 0600); err != nil {
		log.Error().Msgf("Failed to write to OpenVPN control file \"%s\": %s",
			validator.controlFile,
			err)
	}
}
