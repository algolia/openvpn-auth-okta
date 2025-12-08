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

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/phuslu/log"
)

// checkAllowedGroups validates user membership in required Okta groups.
//
// If ApiConfig.AllowedGroups is configured, this function:
//  1. Fetches all groups the user belongs to via Okta API
//  2. Checks if user is member of at least one allowed group
//  3. Returns error if no matching group found
//
// Group matching is case-sensitive and exact (no wildcards or regex).
//
// API endpoint: GET /api/v1/users/{username}/groups
// See: https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
//
// Parameters: None (uses auth.ApiConfig.AllowedGroups and auth.UserConfig.Username)
//
// Returns:
//   - nil: User belongs to at least one allowed group, OR no groups configured
//   - error: User not in allowed groups, API error, or invalid response
//
// Example configuration:
//
//	AllowedGroups: "vpn-users,developers,admins"
//
func (auth *OktaApiAuth) checkAllowedGroups() error {
	log.Trace().Msg("oktaApiAuth.checkAllowedGroups()")
	// https://developer.okta.com/docs/reference/api/users/#request-parameters-8
	if auth.ApiConfig.AllowedGroups != "" {
		validate := validator.New(validator.WithRequiredStructEnabled())
		code, apiRes, err := auth.oktaReq(http.MethodGet, fmt.Sprintf("/users/%s/groups", auth.UserConfig.Username), nil)
		if err != nil {
			return err
		}
		if code != 200 && code != 202 {
			var authResErr ErrorResponse
			if err = json.Unmarshal(apiRes, &authResErr); err == nil {
				if err = validate.Struct(authResErr); err == nil {
					log.Error().Msgf("error fetching user's group list: %s", authResErr.Summary)
				}
			}
			return errors.New("invalid HTTP status code")
		}

		var groupRes []OktaGroup
		if err = json.Unmarshal(apiRes, &groupRes); err != nil {
			log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
			return err
		}

		var groups = OktaGroups{Groups: groupRes}
		if err = validate.Struct(groups); err != nil {
			log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
			return errors.New("invalid group list return by API")
		}

		var aGroups = strings.Split(auth.ApiConfig.AllowedGroups, ",")
		for _, uGroup := range groupRes {
			gName := uGroup.Profile.Name
			if slices.Contains(aGroups, gName) {
				log.Debug().Msgf("is a member of AllowedGroup %s", gName)
				return nil
			}
		}
		return errors.New("not member of an AllowedGroup")
	}
	return nil
}

// getUserFactors categorizes available MFA factors into TOTP and Push lists.
//
// Parses the factors from pre-authentication response and separates them by type:
//  - TOTP factors: Only included if user provided a passcode
//  - Push factors: Always included if available
//  - Other factor types: Logged and skipped (not supported)
//
// This separation enables the validator to:
//  - Try TOTP first when passcode provided
//  - Fall back to Push if configured
//  - Skip TOTP factors when no passcode available
//
// Supported factor types:
//  - "token:software:totp": TOTP authenticator apps (Google Authenticator, Okta Verify TOTP)
//  - "push": Push notifications (Okta Verify)
//
// Parameters:
//   - preAuthRes: Pre-authentication response containing user's enrolled factors
//
// Returns:
//   - factorsTOTP: List of TOTP factors (empty if no passcode provided)
//   - factorsPush: List of Push factors (empty if none available)
func (auth *OktaApiAuth) getUserFactors(preAuthRes PreAuthResponse) (factorsTOTP []AuthFactor, factorsPush []AuthFactor) {
	log.Trace().Msg("oktaApiAuth.getUserFactors()")
	for _, f := range preAuthRes.Embedded.Factors {
		switch f.Type {
		case "token:software:totp":
			if auth.UserConfig.Passcode != "" {
				factorsTOTP = append(factorsTOTP, f)
			}
		case "push":
			factorsPush = append(factorsPush, f)
		default:
			log.Debug().Msgf("unsupported factortype: %s, skipping", f.Type)
		}
	}
	return
}

// preChecks performs group validation and primary authentication.
//
// This function executes the preliminary steps before MFA verification:
//  1. Validates user group membership (if AllowedGroups configured)
//  2. Calls Okta primary authentication endpoint with username/password
//  3. Returns pre-authentication response for status/MFA processing
//
// The pre-authentication response indicates:
//  - Whether username/password are valid
//  - User account status (active, locked, password expired, etc.)
//  - MFA requirements and available factors
//  - State token for continuing the authentication flow
//
// Parameters: None (uses auth.ApiConfig and auth.UserConfig)
//
// Returns:
//   - PreAuthResponse: Okta's authentication response
//   - error: Group check failed or API error
//
// Caller should inspect PreAuthResponse.Status to determine next steps.
func (auth *OktaApiAuth) preChecks() (PreAuthResponse, error) {
	log.Trace().Msg("oktaApiAuth.preChecks()")
	if err := auth.checkAllowedGroups(); err != nil {
		log.Error().Msgf("allowed group verification error: %s", err)
		return PreAuthResponse{}, err
	}

	code, apiRes, err := auth.preAuth()
	if err != nil {
		log.Error().Msgf("Error connecting to the Okta API: %s", err)
		return PreAuthResponse{}, err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	if code != 200 && code != 202 {
		if code == 429 {
			log.Warn().Msg("pre-authentication failed: rate limited")
			return PreAuthResponse{}, errors.New("pre-authentication rate limited")
		}

		var preAuthResErr ErrorResponse
		if err = json.Unmarshal(apiRes, &preAuthResErr); err == nil {
			if err = validate.Struct(preAuthResErr); err == nil {
				log.Warn().Msgf("pre-authentication failed: %s", preAuthResErr.Summary)
				return PreAuthResponse{}, errors.New("pre-authentication failed")
			}
		}
	}

	var preAuthRes PreAuthResponse
	if err = json.Unmarshal(apiRes, &preAuthRes); err != nil {
		log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
		return PreAuthResponse{}, err
	}

	if err = validate.Struct(preAuthRes); err != nil {
		log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
		return PreAuthResponse{}, err
	}

	return preAuthRes, nil
}
