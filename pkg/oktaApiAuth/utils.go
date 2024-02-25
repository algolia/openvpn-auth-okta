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

// Checks that the user belongs to the allowed groups list provided in the conf
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

		var aGroups []string = strings.Split(auth.ApiConfig.AllowedGroups, ",")
		for _, uGroup := range groupRes {
			gName := uGroup.Profile.Name
			if slices.Contains(aGroups, gName) {
				log.Debug().Msgf("is a member of AllowedGroup %s", gName)
				return nil
			}
		}
		return errors.New("Not mmember of an AllowedGroup")
	}
	return nil
}

// Parse the pre authentication api response and create 2 factor lists:
// one for the TOTP factors and one for the Push factors
func (auth *OktaApiAuth) getUserFactors(preAuthRes PreAuthResponse) (factorsTOTP []AuthFactor, factorsPush []AuthFactor) {
	log.Trace().Msg("oktaApiAuth.getUserFactors()")
	for _, f := range preAuthRes.Embedded.Factors {
		if f.Type == "token:software:totp" {
			if auth.UserConfig.Passcode != "" {
				factorsTOTP = append(factorsTOTP, f)
			}
		} else if f.Type == "push" {
			factorsPush = append(factorsPush, f)
		} else {
			log.Debug().Msgf("unsupported factortype: %s, skipping", f.Type)
		}
	}
	return
}

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
