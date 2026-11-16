// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2024-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaApiAuth

import "errors"

var (
	// errPushFailed indicates all Push MFA factors failed or timed out
	errPushFailed = errors.New("push MFA failed")

	// errTOTPFailed indicates all TOTP MFA factors failed (invalid codes)
	errTOTPFailed = errors.New("TOTP MFA failed")

	// errMFAUnavailable indicates no suitable MFA factors were available
	// (e.g., no TOTP when passcode provided, no Push without passcode)
	errMFAUnavailable = errors.New("no MFA factor available")

	// errMFARequired indicates authentication succeeded without MFA
	// but ApiConfig.MFARequired is true (policy enforcement)
	errMFARequired = errors.New("MFA required")

	// errUserLocked indicates the Okta account is locked out
	errUserLocked = errors.New("user locked out")

	// errPasswordExpired indicates the user must reset their password
	errPasswordExpired = errors.New("user password expired")

	// errEnrollNeeded indicates the user must enroll in MFA before authenticating
	errEnrollNeeded = errors.New("needs to enroll")
)

// ErrorResponse represents an Okta API error response.
//
// Returned by Okta API when requests fail (4xx/5xx status codes).
// Contains structured error information for debugging and user feedback.
//
// See: https://developer.okta.com/docs/reference/error-codes/
type ErrorResponse struct {
	// Code is the Okta error code (e.g., "E0000004" for authentication failed)
	Code string `json:"errorCode" validate:"required"`

	// Summary is a human-readable error description
	Summary string `json:"errorSummary" validate:"required"`

	// Link is a URL to Okta documentation for this error
	Link string `json:"errorLink" validate:"required"`

	// Id is a unique identifier for this error instance (for support)
	Id string `json:"errorId" validate:"required"`

	// Causes contains detailed error reasons (may be empty)
	Causes []ErrorCauses `json:"errorCauses" validate:"required"`
}

// ErrorCauses provides detailed reasons for an Okta API error.
//
// Part of ErrorResponse, contains specific failure details.
// May be empty for some error types.
type ErrorCauses struct {
	// Summary describes the specific cause of the error
	Summary string `json:"errorSummary"`
}

// PreAuthResponse represents the response from Okta's primary authentication endpoint.
//
// Returned by /api/v1/authn endpoint after submitting username/password.
// Indicates authentication status and available MFA factors.
//
// See: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
type PreAuthResponse struct {
	// Status indicates the authentication state:
	//  - "SUCCESS": Authenticated (no MFA or MFA not required)
	//  - "MFA_REQUIRED": Must verify MFA factor
	//  - "MFA_CHALLENGE": MFA verification in progress
	//  - "MFA_ENROLL": User must enroll in MFA first
	//  - "PASSWORD_EXPIRED": Must reset password
	//  - "LOCKED_OUT": Account locked
	Status string `json:"status" validate:"required"`

	// Token is the state token for continuing the authentication transaction.
	// Required for MFA verification and transaction cancellation.
	// Empty for SUCCESS and LOCKED_OUT states.
	Token string `json:"stateToken"`

	// Embedded contains nested response data (e.g., available MFA factors)
	Embedded PreAuthEmbedded `json:"_embedded"`
}

// PreAuthEmbedded contains nested data from pre-authentication response.
//
// Part of PreAuthResponse, holds lists of available authentication factors.
type PreAuthEmbedded struct {
	// Factors is the list of MFA factors available to the user.
	// May include TOTP (token:software:totp) and Push factors.
	// Empty if no MFA configured or not required.
	Factors []AuthFactor `json:"factors"`
}

// AuthFactor represents an MFA factor available to or enrolled by a user.
//
// Returned in PreAuthResponse._embedded.factors list.
// Each factor can be verified via the /api/v1/authn/factors/{id}/verify endpoint.
type AuthFactor struct {
	// Id is the unique identifier for this factor instance.
	// Used in factor verification API calls.
	// Example: "opf3hkfocI4JTLAju0g4"
	Id string `json:"id" validate:"required"`

	// Type is the factor type identifier:
	//  - "token:software:totp": Time-based one-time password (Google Authenticator, etc.)
	//  - "push": Okta Verify Push notification
	//  - Other types exist but are not currently supported
	Type string `json:"factorType" validate:"required"`

	// Provider is the factor provider name:
	//  - "OKTA": Okta Verify
	//  - "GOOGLE": Google Authenticator
	//  - Others may exist depending on Okta configuration
	Provider string `json:"provider" validate:"required"`
}

// AuthResponse represents the response from an MFA factor verification attempt.
//
// Returned by /api/v1/authn/factors/{id}/verify endpoint.
// Indicates whether MFA verification succeeded, failed, or is pending.
type AuthResponse struct {
	// Status indicates the overall authentication state:
	//  - "SUCCESS": MFA verified, authentication complete
	//  - "MFA_CHALLENGE": Verification attempt processed (check Result)
	Status string `json:"status" validate:"required"`

	// Token is the state token for the authentication transaction.
	// Used for polling Push status or cancelling the transaction.
	Token string `json:"stateToken"`

	// Result indicates the MFA verification result:
	//  - "SUCCESS": Factor verified successfully
	//  - "WAITING": Push notification sent, waiting for user approval
	//  - "REJECTED": User rejected Push notification
	//  - "TIMEOUT": Push notification expired
	//  - Empty string for TOTP (check Status instead)
	Result string `json:"factorResult"`
}

// OktaGroups represents a collection of Okta groups.
//
// Wrapper for the groups array returned by /api/v1/users/{id}/groups endpoint.
// Used for group membership validation when AllowedGroups is configured.
type OktaGroups struct {
	// Groups is the list of groups the user belongs to
	Groups []OktaGroup `json:"groups" validate:"omitempty,dive"`
}

// OktaGroup represents a single Okta group.
//
// Returned in the groups list from /api/v1/users/{id}/groups endpoint.
type OktaGroup struct {
	// Id is the unique identifier for this group
	Id string `json:"id" validate:"required"`

	// Profile contains group metadata (name, description, etc.)
	Profile OktaGroupProfile `json:"profile" validate:"required"`
}

// OktaGroupProfile contains metadata about an Okta group.
//
// Part of OktaGroup, provides human-readable group information.
type OktaGroupProfile struct {
	// Name is the group display name (case-sensitive).
	// Compared against AllowedGroups configuration.
	// Example: "vpn-users", "developers"
	Name string `json:"name" validate:"required"`
}
