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

// Returns an initialized oktaApiAuth
func New() *OktaApiAuth {
	/*
		utsname := unix.Utsname{}
		_ = unix.Uname(&utsname)
		userAgent := fmt.Sprintf("OktaOpenVPN/2.1.0 (%s %s) Go-http-client/%s",
			utsname.Sysname,
			utsname.Release,
			runtime.Version()[2:])
		fmt.Printf("agent: %s\n", userAgent)

		using dynamic user agent does not work ....
		so for now use a const var
	*/

	return &OktaApiAuth{
		ApiConfig: &OktaAPIConfig{
			AllowUntrustedUsers: false,
			MFARequired:         false,
			MFAPushMaxRetries:   20,
			MFAPushDelaySeconds: 3,
			AllowedGroups:       "",
			TOTPFallbackToPush:  false,
		},
		UserConfig: &OktaUserConfig{},
		userAgent:  userAgent,
	}
}

// Iterates on the factor list provided and tries to authenticate the user
// exit with no error at the first successful factor auth
func (auth *OktaApiAuth) verifyFactors(stateToken string, factors []AuthFactor, factorType string) (err error) {
	log.Trace().Msgf("oktaApiAuth.verifyFactors() %s", factorType)
	nbFactors := len(factors)
	for count, factor := range factors {
		log.Debug().Msgf("verifying %s factor nb %d", factorType, count)
		authRes, err := auth.doAuthFirstStep(factor, count, nbFactors, stateToken, factorType)
		if err != nil {
			if !errors.Is(err, errContinue) {
				return err
			}
			continue
		}
		log.Debug().Msgf("%s %s MFA, Result: %s", factor.Provider, factorType, authRes.Result)

		if factorType == "Push" {
			if authRes.Result != "WAITING" {
				if count == nbFactors-1 {
					return errPushFailed
				}
				continue
			}
			authRes, err = auth.waitForPush(factor, count, nbFactors, stateToken)
			if err != nil {
				if !errors.Is(err, errContinue) {
					return err
				}
				continue
			}
			log.Debug().Msgf("%s Push MFA, waitForPush Result: %s", factor.Provider, authRes.Result)
		}

		if authRes.Status == "SUCCESS" {
			log.Info().Msgf("authenticated with %s %s MFA", factor.Provider, factorType)
			return nil
		}

		if count == nbFactors-1 {
			log.Error().Msgf("%s %s MFA authentication failed: %s",
				factor.Provider,
				factorType,
				authRes.Result)
			return fmt.Errorf("%s MFA failed", factorType)
		}
		log.Warn().Msgf("%s %s MFA authentication failed: %s",
			factor.Provider,
			factorType,
			authRes.Result)
	}
	// Reached only when the list of factors provided is empty
	log.Debug().Msgf("No %s MFA available", factorType)
	return fmt.Errorf("No %s MFA available", factorType)
}

// Gather the list of factors available from the pre authentication api response,
// if the user provided a TOTP in its passwordd string, try TOTP MFA
// otherwise try Push MFA
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
			if err.Error() != "No TOTP MFA available" {
				auth.cancelAuth(preAuthRes.Token)
				return err
			}
			goto ERR
		}
		return nil
	}

PUSH:
	if err = auth.verifyFactors(preAuthRes.Token, factorsPush, "Push"); err != nil {
		if err.Error() != "No Push MFA available" {
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

// Do a full authentication transaction: preAuth, doAuth (when needed), cancelAuth (when needed)
// returns nil if has been validated by Okta API, an error otherwise
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
		return errors.New("Unknown preauth status")
	}
}
