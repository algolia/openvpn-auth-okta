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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phuslu/log"
)

const passcodeLen int = 6

// parsePassword extracts TOTP passcode from the end of the user's password.
//
// OpenVPN users can append their 6-digit TOTP code to their password for MFA.
// This function detects this pattern and splits the password into two parts:
//   - userConfig.Password: the actual password (without TOTP)
//   - userConfig.Passcode: the 6-digit TOTP code
//
// The function respects the PasscodeSeparator configuration:
//   - If separator is empty: extracts last 6 digits if present (e.g., "mypass123456")
//   - If separator is set (e.g., "+"): requires separator before TOTP (e.g., "mypass+123456")
//   - If pattern doesn't match: leaves password unchanged, no TOTP extracted
//
// Example:
//
//	Password: "correcthorsebatterystaple123456"
//	Result: Password="correcthorsebatterystaple", Passcode="123456"
func (validator *OktaOpenVPNValidator) parsePassword() {
	log.Trace().Msg("validator.parsePassword()")
	separator := validator.api.ApiConfig.PasscodeSeparator
	// If the password provided by the user is longer than a OTP (6 cars)
	// and the last 6 caracters are digits
	// then extract the user password (first) and the OTP
	userConfig := validator.api.UserConfig

	r, _ := regexp.Compile("[0-9]{" + strconv.Itoa(passcodeLen) + "}$")
	idx := r.FindStringIndex(userConfig.Password)

	if idx != nil {
		if len(separator) == 1 && idx[0]-1 > 0 && userConfig.Password[idx[0]-1] == separator[0] {
			userConfig.Passcode = userConfig.Password[idx[0]:]
			userConfig.Password = userConfig.Password[0 : idx[0]-1]
		} else if len(separator) == 0 {
			userConfig.Passcode = userConfig.Password[idx[0]:]
			userConfig.Password = userConfig.Password[0:idx[0]]
		} else {
			log.Debug().Msgf("no TOTP found in password")
		}
	} else {
		log.Debug().Msgf("no TOTP found in password")
	}
}

// checkControlFilePerm validates OpenVPN control file security permissions.
//
// This is a critical security check for deferred plugin mode. The control file
// contains the authentication result (1=success, 0=failure). If the file or its
// directory is writable by group/other users, a local attacker could modify the
// result and bypass authentication.
//
// Security requirements enforced:
//   - Control file must not be group writable (prevents tampering by same group)
//   - Control file must not be world writable (prevents tampering by any user)
//   - Parent directory must not be group/world writable (prevents file replacement)
//
// This follows OpenVPN's security guidelines for deferred plugin authentication.
// See: https://openvpn.net/community-resources/using-alternative-authentication-methods/
//
// Returns error if permissions are insecure or file path is empty.
func (validator *OktaOpenVPNValidator) checkControlFilePerm() error {
	log.Trace().Msg("validator.checkControlFilePerm()")
	if validator.controlFile == "" {
		return errors.New("unknown control file")
	}

	if !checkNotWritable(validator.controlFile) {
		log.Error().Msgf("Refusing to authenticate. The file \"%s\" must not be writable by non-owners.",
			validator.controlFile)
		return errors.New("control file writable by non-owners")
	}
	dirName := filepath.Dir(validator.controlFile)
	if !checkNotWritable(dirName) {
		log.Error().Msgf("Refusing to authenticate. The directory containing the file \"%s\" must not be writable by non-owners.",
			validator.controlFile)
		return errors.New("control file dir writable by non-owners")
	}
	return nil
}

// getEnv retrieves an environment variable value with fallback support.
//
// Unlike os.Getenv, this function returns the fallback value if the
// environment variable is not set OR is set to an empty string.
//
// Parameters:
//   - key: environment variable name
//   - fallback: value to return if key is not set or empty
//
// Returns the environment variable value, or fallback if not found/empty.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// checkUsernameFormat validates username against OpenVPN security requirements.
//
// OpenVPN documentation requires that usernames contain only safe characters
// to prevent injection attacks and malformed input. This function enforces
// that restriction.
//
// Allowed characters:
//   - Alphanumeric: a-z, A-Z, 0-9
//   - Underscore: _
//   - Dash: -
//   - Dot: .
//   - At sign: @
//
// Reference: OpenVPN manual section on auth-user-pass-verify security
//
// Returns true if username format is valid, false otherwise.
func checkUsernameFormat(name string) bool {
	log.Trace().Msg("validator.checkUsernameFormat()")
	/* OpenVPN doc says:
	To protect against a client passing a maliciously formed username or password string,
	the username string must consist only of these characters:
	alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
	*/
	match, _ := regexp.MatchString(`^([[:alnum:]]|[_\-\.@])*$`, name)
	return match
}

// checkNotWritable verifies that a file or directory is not writable by group or others.
//
// This security check prevents privilege escalation and tampering attacks.
// If a file/directory is writable by non-owners, attackers in the same group
// or any local user could modify critical files.
//
// Checks Unix permission bits:
//   - S_IWGRP (020): Group write permission
//   - S_IWOTH (002): Other write permission
//
// Returns true if file/directory is safe (not group/world writable), false otherwise.
// Returns false if path does not exist or stat fails.
func checkNotWritable(path string) bool {
	sIWGRP := 0b000010000 // Group write permissions
	sIWOTH := 0b000000010 // Other write permissions

	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	fileMode := fileInfo.Mode().Perm()
	if int(fileMode)&sIWGRP == sIWGRP || int(fileMode)&sIWOTH == sIWOTH {
		return false
	}
	return true
}

// removeEmptyStrings filters out empty strings from a slice.
//
// Used for cleaning up file content (via-file, pinset.cfg) where empty
// lines should be ignored.
//
// Parameters:
//   - s: input slice that may contain empty strings
//
// Returns a new slice containing only non-empty strings, preserving order.
func removeEmptyStrings(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

// removeComments filters out comment lines from a slice.
//
// Lines starting with # (optionally preceded by whitespace) are considered
// comments and removed. Used for processing pinset.cfg and other config files.
//
// Parameters:
//   - s: input slice that may contain comment lines
//
// Returns a new slice with comment lines removed, preserving order.
func removeComments(s []string) []string {
	var r []string
	reg, _ := regexp.Compile(`^[[:blank:]]*#`)
	for _, str := range s {
		if match := reg.MatchString(`^[[:blank:]]*#`); !match {
			r = append(r, str)
		}
	}
	return r
}

// setLogUser updates the log formatter to include the authenticated username.
//
// Called after credentials are loaded to enhance audit trail. All subsequent
// log messages will include the username being authenticated, making it easier
// to correlate log entries with specific user authentication attempts.
//
// Log format after this call:
//
//	<timestamp> [okta-auth-validator:<sessionID>](<LEVEL>): [<username>] <message>
//
// Example:
//
//	Mon Jan 2 15:04:05 2006 [okta-auth-validator:uuid-123](INFO): [user@example.com] authenticated with Okta TOTP MFA
func (validator *OktaOpenVPNValidator) setLogUser() {
	log.DefaultLogger.Writer.(*log.ConsoleWriter).Formatter = func(w io.Writer, a *log.FormatterArgs) (int, error) {
		return fmt.Fprintf(
			w,
			"%s [okta-auth-validator:%s](%s): [%s] %s\n",
			a.Time,
			validator.sessionId,
			strings.ToUpper(a.Level),
			validator.api.UserConfig.Username,
			a.Message)
	}
}

// initLogFormatter initializes the global logger with session-specific formatting.
//
// Called during validator creation (New) to set up structured logging for this
// authentication session. Each validator instance gets a unique session UUID that
// appears in all log messages, enabling correlation of log entries.
//
// Parameters:
//   - level: logging verbosity (TRACE, DEBUG, INFO, WARN, ERROR)
//
// Initial log format (before credentials loaded):
//
//	<timestamp> [okta-auth-validator:<sessionID>](<LEVEL>): <message>
//
// The formatter is updated by setLogUser() after credentials are available.
func (validator *OktaOpenVPNValidator) initLogFormatter(level log.Level) {
	log.DefaultLogger = log.Logger{
		Level:      level,
		Caller:     1,
		TimeFormat: time.ANSIC,
		Writer: &log.ConsoleWriter{
			ColorOutput: false,
			Formatter: func(w io.Writer, a *log.FormatterArgs) (int, error) {
				return fmt.Fprintf(
					w,
					"%s [okta-auth-validator:%s](%s): %s\n",
					a.Time,
					validator.sessionId,
					strings.ToUpper(a.Level),
					a.Message)
			},
		},
	}
}
