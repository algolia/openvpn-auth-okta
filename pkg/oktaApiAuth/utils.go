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
	log "github.com/sirupsen/logrus"
)

func (auth *OktaApiAuth) checkAllowedGroups() error {
	// https://developer.okta.com/docs/reference/api/users/#request-parameters-8
	if auth.ApiConfig.AllowedGroups != "" {
		apiRes, err := auth.oktaReq(http.MethodGet, fmt.Sprintf("/users/%s/groups", auth.UserConfig.Username), nil)
		if err != nil {
			return err
		}

		var groupRes []OktaGroup
		err = json.Unmarshal(apiRes, &groupRes)
		if err != nil {
			log.Errorf("Error unmarshaling Okta API response: %s", err)
			return err
		}

		var aGroups []string = strings.Split(auth.ApiConfig.AllowedGroups, ",")
		for _, uGroup := range groupRes {
			gName := uGroup.Profile.Name
			if slices.Contains(aGroups, gName) {
				log.Debugf("is a member of AllowedGroup %s", gName)
				return nil
			}
		}
		return errors.New("Not mmember of an AllowedGroup")
	}
	return nil
}

func (auth *OktaApiAuth) getUserFactors(preAuthRes PreAuthResponse) (factorsTOTP []AuthFactor, factorsPush []AuthFactor) {
	for _, f := range preAuthRes.Embedded.Factors {
		if f.Type == "token:software:totp" {
			if auth.UserConfig.Passcode != "" {
				factorsTOTP = append(factorsTOTP, f)
			}
		} else if f.Type == "push" {
			factorsPush = append(factorsPush, f)
		} else {
			log.Debugf("unsupported factortype: %s, skipping", f.Type)
		}
	}
	return
}

func (auth *OktaApiAuth) preChecks() (PreAuthResponse, error) {
	err := auth.checkAllowedGroups()
	if err != nil {
		log.Errorf("allowed group verification error: %s", err)
		return PreAuthResponse{}, err
	}

	apiRes, err := auth.preAuth()
	if err != nil {
		log.Errorf("Error connecting to the Okta API: %s", err)
		return PreAuthResponse{}, err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	var preAuthResErr ErrorResponse
	err = json.Unmarshal(apiRes, &preAuthResErr)
	if err == nil {
		err = validate.Struct(preAuthResErr)
		if err == nil {
			log.Warningf("pre-authentication failed: %s", preAuthResErr.Summary)
			return PreAuthResponse{}, errors.New("pre-authentication failed")
		}
	}

	var preAuthRes PreAuthResponse
	err = json.Unmarshal(apiRes, &preAuthRes)
	if err != nil {
		log.Errorf("Error unmarshaling Okta API response: %s", err)
		return PreAuthResponse{}, err
	}
	err = validate.Struct(preAuthRes)
	if err != nil {
		log.Errorf("Error unmarshaling Okta API response: %s", err)
		return PreAuthResponse{}, err
	}

	return preAuthRes, nil
}
