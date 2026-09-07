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
	"errors"
	"fmt"

	"github.com/phuslu/log"
)

// New creates a new OktaApiAuth instance with default configuration values.
//
// Returns an initialized OktaApiAuth with:
//   - ApiConfig populated with secure defaults
//   - UserConfig initialized but empty (populate before calling Auth)
//   - pool uninitialized (call InitPool before Auth)
//
// Default configuration:
//   - AllowUntrustedUsers: false (require SSL certificates)
//   - MFARequired: false (allow authentication without MFA if Okta permits)
//   - MFAPushMaxRetries: 20 (60 seconds with default delay)
//   - MFAPushDelaySeconds: 3 (check Push MFA every 3 seconds)
//   - AllowedGroups: "" (no group restriction)
//   - TOTPFallbackToPush: false (don't retry with Push if TOTP fails)
//   - PasscodeSeparator: "" (extract last 6 digits as TOTP)
//
// The returned instance must be further configured:
//  1. Set ApiConfig.Url and ApiConfig.Token (required)
//  2. Load ApiConfig.AssertPin from pinset.cfg
//  3. Populate UserConfig with credentials
//  4. Call InitPool() to initialize HTTP client with TLS pinning
//  5. Call Auth() to perform authentication
func New() *OktaApiAuth {

	return &OktaApiAuth{
		ApiConfig: &OktaAPIConfig{
			AllowUntrustedUsers: false,
			MFARequired:         false,
			MFAPushMaxRetries:   20,
			MFAPushDelaySeconds: 3,
			AllowedGroups:       "",
			TOTPFallbackToPush:  false,
			PasscodeSeparator:   "",
		},
		UserConfig: &OktaUserConfig{},
	}
}

// verifyFactors attempts authentication with a list of MFA factors.
//
// Iterates through the provided factors, attempting verification with each
// until one succeeds or all fail. This enables graceful handling of users
// with multiple factors of the same type (e.g., multiple TOTP apps).
//
// Parameters:
//   - stateToken: Okta authentication transaction state token
//   - factors: List of factors to try (TOTP or Push)
//   - factorType: "TOTP" or "Push" (for logging and error messages)
//
// Behavior:
//   - For TOTP: Immediately verifies passcode against each factor
//   - For Push: Sends notification then polls for user response
//   - Logs warnings for non-final factor failures
//   - Returns error only if all factors fail
//   - Returns success on first successful factor
//
// Error handling:
//   - Uses parseOktaError to suppress errors for non-final factors
//   - Only the last factor's error is returned to caller
//   - This prevents premature failure when multiple factors exist
//
// Returns:
//   - nil: Successfully authenticated with one of the factors
//   - error: All factors failed or no factors provided
func (auth *OktaApiAuth) verifyFactors(stateToken string, factors []AuthFactor, factorType string) (err error) {
	log.Trace().Msgf("oktaApiAuth.verifyFactors() %s", factorType)
	nbFactors := len(factors)
	ftype := factorType
	if factorType == "Push" {
		ftype = "push"
	}
	for count, factor := range factors {
		log.Debug().Msgf("verifying %s factor nb %d", factorType, count)
		authRes, err := auth.doAuthFirstStep(factor, stateToken, factorType)
		err = parseOktaError(err, count, nbFactors)
		if err != nil {
			return err
		}
		log.Debug().Msgf("%s %s MFA (%s), Result: %s",
			factor.Provider,
			factorType,
			factor.Id,
			authRes.Result)

		if factorType == "Push" {
			if authRes.Result != "WAITING" {
				if count == nbFactors-1 {
					return errPushFailed
				}
				continue
			}
			authRes, err = auth.waitForPush(factor, count, nbFactors, stateToken)
			err = parseOktaError(err, count, nbFactors)
			if err != nil {
				return err
			}
			if authRes.Result != "" {
				log.Debug().Msgf("%s Push MFA, waitForPush Result: %s", factor.Provider, authRes.Result)
			}
		}

		if authRes.Status == "SUCCESS" {
			log.Info().Msgf("authenticated with %s %s MFA", factor.Provider, factorType)
			return nil
		}

		var mfaErr error
		if authRes.Result != "" {
			mfaErr = fmt.Errorf("%s %s MFA authentication failed: %s, %w",
				factor.Provider,
				factorType,
				authRes.Result,
				fmt.Errorf("%s MFA failed", ftype))
		} else {
			mfaErr = fmt.Errorf("%s %s MFA authentication failed, %w",
				factor.Provider,
				factorType,
				fmt.Errorf("%s MFA failed", ftype))
		}

		err = parseOktaError(mfaErr, count, nbFactors)
		if err != nil {
			return err
		}
	}
	// Reached only when the list of factors provided is empty
	log.Debug().Msgf("No %s MFA available", factorType)
	return fmt.Errorf("no %s MFA available", ftype)
}

// validateUserMFA orchestrates MFA verification based on available factors and user input.
//
// Determines which MFA factors to attempt based on:
//   - Available factors from pre-authentication (factorsTOTP, factorsPush)
//   - Whether user provided a TOTP passcode
//   - TOTPFallbackToPush configuration setting
//
// MFA selection logic:
//  1. If passcode provided:
//     a. Try all TOTP factors
//     b. If TOTP fails AND TOTPFallbackToPush=true: try Push factors
//     c. Otherwise: return TOTP error
//  2. If no passcode:
//     a. Try all Push factors
//     b. If none available: return errMFAUnavailable
//
// Transaction management:
//   - Cancels authentication transaction on any error
//   - Prevents abandoned transactions from accumulating in Okta
//
// Parameters:
//   - preAuthRes: Pre-authentication response containing state token and factors
//
// Returns:
//   - nil: MFA verification succeeded
//   - errMFAUnavailable: No suitable factors available for the provided credentials
//   - Other errors: Factor verification failed or API errors
func (auth *OktaApiAuth) validateUserMFA(preAuthRes PreAuthResponse) (err error) {
	log.Trace().Msg("oktaApiAuth.validateUserMFA()")

	factorsTOTP, factorsPush := auth.getUserFactors(preAuthRes)

	if auth.UserConfig.Passcode != "" {
		if err = auth.verifyFactors(preAuthRes.Token, factorsTOTP, "TOTP"); err != nil {
			if auth.ApiConfig.TOTPFallbackToPush {
				// If all TOTP factors failed and fallback to push has been enabled in config
				// try Push MFA authentication
				goto PUSH
			}
			if err.Error() != "no TOTP MFA available" {
				auth.cancelAuth(preAuthRes.Token)
				return err
			}
			goto ERR
		}
		return nil
	}

PUSH:
	if err = auth.verifyFactors(preAuthRes.Token, factorsPush, "Push"); err != nil {
		if err.Error() != "no push MFA available" {
			auth.cancelAuth(preAuthRes.Token)
			return err
		}
		goto ERR
	}
	return nil

ERR:
	log.Error().Msgf("No MFA factor available")
	auth.cancelAuth(preAuthRes.Token)
	return errMFAUnavailable
}

// Auth performs the complete Okta authentication flow with MFA support.
//
// Prerequisites:
//   - ApiConfig must be fully populated (Url, Token, AssertPin, etc.)
//   - UserConfig must contain Username and Password
//   - InitPool() must have been called successfully
//
// Authentication flow:
//  1. Validates user group membership (if AllowedGroups configured)
//  2. Calls Okta pre-authentication endpoint to get user status
//  3. Handles various user states:
//     - SUCCESS: User authenticated (may reject if MFARequired=true)
//     - LOCKED_OUT: Account locked, returns errUserLocked
//     - PASSWORD_EXPIRED: Password needs reset, returns errPasswordExpired
//     - MFA_ENROLL: User must enroll in MFA, returns errEnrollNeeded
//     - MFA_REQUIRED/MFA_CHALLENGE: Proceeds to MFA verification
//  4. For MFA users, attempts verification:
//     - If Passcode provided: tries TOTP factors first
//     - If TOTPFallbackToPush enabled: tries Push on TOTP failure
//     - If no Passcode: tries Push factors
//  5. Cancels transaction on errors (prevents session buildup)
//
// MFA behavior:
//   - Tries all available factors of each type sequentially
//   - Returns on first successful factor
//   - Logs warnings for non-final factor failures
//   - Returns error only if all factors fail
//
// Returns:
//   - nil: Authentication successful
//   - errMFARequired: User succeeded without MFA but MFARequired=true
//   - errUserLocked: Account locked in Okta
//   - errPasswordExpired: User must reset password
//   - errEnrollNeeded: User must enroll in MFA
//   - errMFAUnavailable: No suitable MFA factors available
//   - Other errors: API errors, network issues, invalid responses
//
// All authentication attempts are logged with structured logging.
func (auth *OktaApiAuth) Auth() error {
	log.Trace().Msg("oktaApiAuth.Auth()")
	log.Info().Msgf("Authenticating")
	preAuthRes, err := auth.preChecks()
	if err != nil {
		return err
	}

	switch preAuthRes.Status {
	case "SUCCESS":
		if auth.ApiConfig.MFARequired {
			log.Warn().Msgf("allowed without MFA but MFA is required - rejected")
			return errMFARequired
		}
		return nil

	case "LOCKED_OUT":
		log.Warn().Msgf("is locked out")
		return errUserLocked

	case "PASSWORD_EXPIRED":
		log.Warn().Msgf("password is expired")
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errPasswordExpired

	case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
		log.Warn().Msgf("needs to enroll first")
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errEnrollNeeded

	case "MFA_REQUIRED", "MFA_CHALLENGE":
		log.Debug().Msgf("checking second factor")
		return auth.validateUserMFA(preAuthRes)

	default:
		log.Error().Msgf("unknown preauth status: %s", preAuthRes.Status)
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("unknown preauth status")
	}
}
