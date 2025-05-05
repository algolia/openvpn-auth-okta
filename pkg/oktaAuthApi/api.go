// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaAuthApi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/phuslu/log"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/authApi"
)

func (auth *OktaAuthApi) Setup() (err error) {
	auth.pool, err = authApi.ApiInitPool(auth.ApiConfig)
	return err
}

// only used by validator_test.go
// nolint:unused
func (auth *OktaAuthApi) getPool() *http.Client {
	return auth.pool
}

// Do an http request to the Okta API using the path and payload provided
func (auth *OktaAuthApi) oktaReq(method string, path string, data map[string]string) (code int, jsonBody []byte, err error) {
	u, _ := url.ParseRequestURI(auth.ApiConfig.Url)
	u.Path = fmt.Sprintf("/api/v1%s", path)

	userAgent := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 (OktaOpenVPN)"
	ssws := fmt.Sprintf("SSWS %s", auth.ProviderConfig.Token)

	headers := map[string]string{
		"User-Agent":         userAgent,
		"Sec-Ch-Ua":          `"Chromium";v="119", "Not?A_Brand";v="24"`,
		"Sec-Ch-Ua-Platform": `"Linux"`,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Content-Type":       "application/json",
		"Accept":             "application/json",
		"Authorization":      ssws,
	}
	if auth.UserConfig.ClientIp != "" {
		headers["X-Forwarded-For"] = auth.UserConfig.ClientIp
	}

	var r *http.Request
	var dataReader *bytes.Reader
	if method == http.MethodPost {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Error().Msgf("Error marshaling request payload: %s", err)
			return 0, nil, err
		}
		dataReader = bytes.NewReader(jsonData)
	} else {
		dataReader = bytes.NewReader([]byte{})
	}
	r, err = http.NewRequest(method, u.String(), dataReader)
	if err != nil {
		log.Error().Msgf("Error creating http request: %s", err)
		return 0, nil, err
	}
	for k, v := range headers {
		r.Header.Add(k, v)
	}
	resp, err := auth.pool.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	jsonBody, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msgf("Error reading Okta API response: %s", err)
		return 0, nil, err
	}

	return resp.StatusCode, jsonBody, nil
}

// Call the preauth Okta API endpoint
func (auth *OktaAuthApi) preAuth() (int, []byte, error) {
	// https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
	log.Trace().Msg("oktaAuthApi.preAuth()")
	data := map[string]string{
		"username": auth.UserConfig.Username,
		"password": auth.UserConfig.Password,
	}
	return auth.oktaReq(http.MethodPost, "/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *OktaAuthApi) doAuth(fid string, stateToken string) (int, []byte, error) {
	// https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
	log.Trace().Msg("oktaAuthApi.doAuth()")
	path := fmt.Sprintf("/authn/factors/%s/verify", fid)
	data := map[string]string{
		"fid":        fid,
		"stateToken": stateToken,
		"passCode":   auth.UserConfig.Passcode,
	}
	return auth.oktaReq(http.MethodPost, path, data)
}

// Cancel an authentication transaction
func (auth *OktaAuthApi) cancelAuth(stateToken string) {
	// https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
	log.Trace().Msg("oktaAuthApi.cancelAuth()")
	data := map[string]string{
		"stateToken": stateToken,
	}
	_, _, _ = auth.oktaReq(http.MethodPost, "/authn/cancel", data)
}

// parseAuthResponse takes a doAuth response, unmarshalls it,
// validate the struct fields and return it if validate
func parseAuthResponse(apiRes []byte) (AuthResponse, error) {
	var authRes AuthResponse
	err := json.Unmarshal(apiRes, &authRes)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("Error unmarshaling Okta API response: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(authRes)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("Error unmarshaling Okta API response: %w", err)
	}
	return authRes, nil
}

func (auth *OktaAuthApi) doAuthFirstStep(factor AuthFactor, stateToken string, ftype string) (AuthResponse, error) {
	log.Trace().Msgf("oktaAuthApi.doAuthFirstStep() %s %s", factor.Type, factor.Provider)
	code, apiRes, err := auth.doAuth(factor.Id, stateToken)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("Okta Authentication request error: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	if code != 200 && code != 202 {
		var authResErr ErrorResponse
		var errorSummary string

		if err = json.Unmarshal(apiRes, &authResErr); err == nil {
			err = validate.Struct(authResErr)
			if err == nil {
				if len(authResErr.Causes) > 0 {
					errorSummary = authResErr.Causes[0].Summary
				} else {
					errorSummary = authResErr.Summary
				}
			} else {
				errorSummary = fmt.Sprintf("HTTP status code %d", code)
			}
		} else {
			errorSummary = fmt.Sprintf("HTTP status code %d", code)
		}
		return AuthResponse{}, fmt.Errorf("%s %s (%s): %w",
			factor.Provider,
			ftype,
			errorSummary,
			fmt.Errorf("%s MFA failed", ftype))
	}

	return parseAuthResponse(apiRes)
}

// At first iteration and until the factorResult is different from WAITING
// keep retrying the Push MFA (we are waiting here that the user either accept or reject auth)
func (auth *OktaAuthApi) waitForPush(factor AuthFactor, stateToken string) (authRes AuthResponse, err error) {
	log.Trace().Msgf("oktaAuthApi.waitForPush() %s %s", factor.Type, factor.Provider)

	for checkCount := 0; checkCount == 0 || authRes.Result == "WAITING"; checkCount++ {
		if checkCount >= auth.ProviderConfig.MFAPushMaxRetries {
			return AuthResponse{}, fmt.Errorf("%s %w", factor.Provider, errors.New("Push MFA timeout"))
		}

		time.Sleep(time.Duration(auth.ProviderConfig.MFAPushDelaySeconds) * time.Second)

		code, apiRes, err := auth.doAuth(factor.Id, stateToken)
		if err != nil {
			return AuthResponse{}, fmt.Errorf("Okta Authentication request error: %w", err)
		}
		if code != 200 && code != 202 {
			return AuthResponse{}, fmt.Errorf("%s push MFA invalid HTTP status code %d, %w",
				factor.Provider,
				code,
				errors.New("Push MFA failed"))
		}

		authRes, err = parseAuthResponse(apiRes)
		if err != nil {
			return authRes, err
		}
		log.Debug().Msgf("waiForPush Okta response: {Status: %s, Result:%s}",
			authRes.Status,
			authRes.Result)
	}
	return authRes, nil
}
