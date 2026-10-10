// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaApiAuth

import "net/http"

// OktaAPIConfig holds configuration for Okta API authentication.
//
// This configuration is loaded from api.ini and controls how the validator
// connects to and authenticates against Okta's Authentication API.
//
// All fields are mapped from the [OktaAPI] section of api.ini using struct tags.
type OktaAPIConfig struct {
	// Url is the base URL of your Okta organization.
	// Example: "https://example.okta.com" or "https://example.oktapreview.com"
	// Required field.
	Url string

	// Token is your Okta API token for server-to-server authentication.
	// Generate from Okta Admin Console: Security > API > Tokens.
	// Format: 40-character alphanumeric string.
	// Required field. Keep confidential - grants full API access.
	Token string

	// UsernameSuffix is appended to usernames that don't contain '@'.
	// Example: If set to "example.com" and user logs in as "john.doe",
	// authentication will be attempted for "john.doe@example.com".
	// Optional - leave empty to use usernames as-is.
	UsernameSuffix string

	// AssertPin contains SHA256 fingerprints of allowed Okta server public keys.
	// This enables TLS certificate pinning to prevent MITM attacks.
	// Loaded from pinset.cfg file, one base64-encoded digest per line.
	// Must be updated when Okta rotates certificates.
	AssertPin []string

	// MFARequired enforces MFA for all users.
	// If true and Okta authenticates without MFA challenge, authentication fails.
	// Use this to enforce company-wide MFA policy even if some Okta users
	// don't have MFA configured.
	// Default: false
	MFARequired bool

	// AllowUntrustedUsers permits authentication without SSL client certificates.
	// If false, username must match SSL certificate CN (recommended).
	// If true, username from OpenVPN credentials is trusted (NOT RECOMMENDED).
	// Default: false
	AllowUntrustedUsers bool

	// MFAPushMaxRetries is the maximum polling attempts for Push MFA.
	// Each retry waits MFAPushDelaySeconds before checking again.
	// Total timeout = MFAPushMaxRetries × MFAPushDelaySeconds.
	// Default: 20 (60 seconds with 3-second delays)
	MFAPushMaxRetries int

	// MFAPushDelaySeconds is the wait time between Push MFA poll attempts.
	// Lower values provide faster response but increase API calls.
	// Default: 3 seconds
	MFAPushDelaySeconds int

	// AllowedGroups restricts access to members of specific Okta groups.
	// Comma-separated list of group names (case-sensitive).
	// Example: "vpn-users,developers,admins"
	// If empty, group membership is not checked.
	// Default: "" (no restriction)
	AllowedGroups string

	// TOTPFallbackToPush enables Push MFA retry if TOTP fails.
	// If true and TOTP verification fails, attempts Push MFA as fallback.
	// Useful when users have both factors but mistype TOTP code.
	// Default: false
	TOTPFallbackToPush bool

	// PasscodeSeparator is the character between password and TOTP code.
	// If empty: TOTP extracted as last 6 digits ("password123456").
	// If set (e.g., "+"): requires separator ("password+123456").
	// Must be empty or exactly 1 character.
	// Default: "" (no separator required)
	PasscodeSeparator string
}

// OktaUserConfig contains credentials and metadata for a single authentication attempt.
//
// This struct is populated by the validator package from OpenVPN environment
// variables or via-file, then used by OktaApiAuth during authentication.
type OktaUserConfig struct {
	// Username is the Okta username to authenticate.
	// May have UsernameSuffix appended if configured.
	// Example: "john.doe@example.com"
	Username string

	// Password is the user's Okta password (without TOTP).
	// The validator extracts TOTP passcode before populating this field.
	Password string

	// Passcode is the 6-digit TOTP code for MFA.
	// Extracted from the end of the password string if present.
	// Empty string if no TOTP provided (Push MFA only).
	Passcode string

	// ClientIp is the OpenVPN client's IP address.
	// Sent to Okta API as X-Forwarded-For header for audit/security.
	// Example: "192.168.1.100"
	ClientIp string
}

// OktaApiAuth is the main client for Okta Authentication API.
//
// This struct coordinates the complete authentication flow including:
//   - TLS certificate pinning validation
//   - Pre-authentication to determine MFA requirements
//   - MFA factor verification (TOTP and/or Push)
//   - Group membership validation
//   - Transaction cancellation on errors
//
// Usage:
//
//	auth := oktaApiAuth.New()
//	auth.ApiConfig.Url = "https://example.okta.com"
//	auth.ApiConfig.Token = "your-api-token"
//	auth.UserConfig.Username = "user@example.com"
//	auth.UserConfig.Password = "password123456"  // password + TOTP
//	if err := auth.InitPool(); err != nil {
//	    // TLS pinning failed
//	}
//	if err := auth.Auth(); err != nil {
//	    // Authentication failed
//	}
//
// Thread safety: Not thread-safe. Create separate instances for concurrent authentications.
type OktaApiAuth struct {
	// ApiConfig holds Okta API connection settings.
	// Populated from api.ini configuration file.
	ApiConfig *OktaAPIConfig

	// UserConfig holds credentials for current authentication attempt.
	// Populated from OpenVPN environment or via-file.
	UserConfig *OktaUserConfig

	// pool is the HTTP client with TLS pinning enabled.
	// Initialized by InitPool(), used for all API requests.
	pool *http.Client
}
