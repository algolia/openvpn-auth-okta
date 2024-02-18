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

	log "github.com/sirupsen/logrus"
)

func NewOktaApiAuth() *OktaApiAuth {
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
		},
		UserConfig: &OktaUserConfig{},
		userAgent:  userAgent,
	}
}

func (auth *OktaApiAuth) verifyFactors(stateToken string, factors []AuthFactor, factorType string) (err error) {
	nbFactors := len(factors)
	for count, factor := range factors {
		authRes, err := auth.doAuthFirstStep(factor, count, nbFactors, stateToken, factorType)
		if err != nil {
			if err.Error() != "continue" {
				auth.cancelAuth(stateToken)
				return err
			}
			continue
		}

		if factorType == "Push" {
			if authRes.Result != "WAITING" {
				if count == nbFactors-1 {
					auth.cancelAuth(stateToken)
					return errors.New("Push MFA failed")
				}
				continue
			}
			authRes, err = auth.waitForPush(factor, count, nbFactors, stateToken)
			if err != nil {
				if err.Error() != "continue" {
					auth.cancelAuth(stateToken)
					return err
				}
				continue
			}
		}

		if authRes.Status == "SUCCESS" {
			log.Infof("authenticated with %s %s MFA", factor.Provider, factorType)
			return nil
		}

		if count == nbFactors-1 {
			log.Errorf("%s %s MFA authentication failed: %s",
				factor.Provider,
				factorType,
				authRes.Result)
			auth.cancelAuth(stateToken)
			return fmt.Errorf("%s MFA failed", factorType)
		}
		log.Warningf("%s %s MFA authentication failed: %s",
			factor.Provider,
			factorType,
			authRes.Result)
	}
	// We'll only be there if a passcode is provided and no TOTP factor is available
	return fmt.Errorf("No %s MFA available", factorType)
}

func (auth *OktaApiAuth) validateUserMFA(preAuthRes PreAuthResponse) (err error) {
	factorsTOTP, factorsPush := auth.getUserFactors(preAuthRes)

	if auth.UserConfig.Passcode != "" {
		if err = auth.verifyFactors(preAuthRes.Token, factorsTOTP, "TOTP"); err != nil {
			if err.Error() != "No TOTP MFA available" {
				return err
			}
			goto ERR
		}
		return nil
	}

	if err = auth.verifyFactors(preAuthRes.Token, factorsPush, "Push"); err == nil {
		return nil
	} else if err.Error() != "No Push MFA available" {
		return err
	}

ERR:
	log.Errorf("No MFA factor available")
	auth.cancelAuth(preAuthRes.Token)
	return errors.New("No MFA factor available")
}

// Do a full authentication transaction: preAuth, doAuth (when needed), cancelAuth (when needed)
// returns nil if has been validated by Okta API, an error otherwise
func (auth *OktaApiAuth) Auth() error {
	log.Infof("Authenticating")
	preAuthRes, err := auth.preChecks()
	if err != nil {
		return err
	}

	switch preAuthRes.Status {
	case "SUCCESS":
		if auth.ApiConfig.MFARequired {
			log.Warningf("allowed without MFA but MFA is required - rejected")
			return errors.New("MFA required")
		}
		return nil

	case "LOCKED_OUT":
		log.Warningf("is locked out")
		return errors.New("User locked out")

	case "PASSWORD_EXPIRED":
		log.Warningf("password is expired")
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("User password expired")

	case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
		log.Warningf("needs to enroll first")
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("Needs to enroll")

	case "MFA_REQUIRED", "MFA_CHALLENGE":
		log.Debugf("checking second factor")
		return auth.validateUserMFA(preAuthRes)

	default:
		log.Errorf("unknown preauth status: %s", preAuthRes.Status)
		if preAuthRes.Token != "" {
			auth.cancelAuth(preAuthRes.Token)
		}
		return errors.New("Unknown preauth status")
	}
}
