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
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/phuslu/log"
)

// Prepare an http client with a safe TLS config
// validate the server public key against our list of pinned key fingerprint
func (auth *OktaApiAuth) InitPool() error {
	log.Trace().Msg("oktaApiAuth.InitPool()")
	if rawURL, err := url.Parse(auth.ApiConfig.Url); err != nil {
		return err
	} else {
		var port string
		if port = rawURL.Port(); port == "" {
			port = "443"
		}
		// Connect to the server, fetch its public key and validate it against the
		// base64 digest in pinset slice
		tcpURL := fmt.Sprintf("%s:%s", rawURL.Hostname(), port)
		conn, err := tls.Dial("tcp", tcpURL, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Error().Msgf("Error in Dial: %s", err)
			return err
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			if !cert.IsCA {
				// Compute public key base64 digest
				derPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return err
				}
				pubKeySha := sha256.Sum256(derPubKey)
				digest := base64.StdEncoding.EncodeToString([]byte(string(pubKeySha[:])))

				if !slices.Contains(auth.ApiConfig.AssertPin, digest) {
					log.Error().Msgf("Refusing to authenticate because host %s failed %s\n%s\n%s",
						rawURL.Hostname(),
						"a TLS public key pinning check.",
						"Update your \"pinset.cfg\" file or ",
						"contact support@okta.com with this error message")
					return errors.New("Server pubkey does not match pinned keys")
				}
			}
		}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.2 safe cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			// TLS 1.3 cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	t := &http.Transport{
		MaxIdleConns:        5,
		MaxConnsPerHost:     5,
		MaxIdleConnsPerHost: 5,
		TLSClientConfig:     tlsCfg,
	}
	auth.pool = &http.Client{
		Timeout:   10 * time.Second,
		Transport: t,
	}
	return nil
}

// only used by validator_test.go
// TODO: find a clean way to only export this for tests
func (auth *OktaApiAuth) Pool() *http.Client {
	return auth.pool
}

// Do an http request to the Okta API using the path and payload provided
func (auth *OktaApiAuth) oktaReq(method string, path string, data map[string]string) (code int, jsonBody []byte, err error) {
	u, _ := url.ParseRequestURI(auth.ApiConfig.Url)
	u.Path = fmt.Sprintf("/api/v1%s", path)

	ssws := fmt.Sprintf("SSWS %s", auth.ApiConfig.Token)
	headers := map[string]string{
		"User-Agent":    auth.userAgent,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Authorization": ssws,
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
func (auth *OktaApiAuth) preAuth() (int, []byte, error) {
	// https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
	log.Trace().Msg("oktaApiAuth.preAuth()")
	data := map[string]string{
		"username": auth.UserConfig.Username,
		"password": auth.UserConfig.Password,
	}
	return auth.oktaReq(http.MethodPost, "/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *OktaApiAuth) doAuth(fid string, stateToken string) (int, []byte, error) {
	// https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
	log.Trace().Msg("oktaApiAuth.doAuth()")
	path := fmt.Sprintf("/authn/factors/%s/verify", fid)
	data := map[string]string{
		"fid":        fid,
		"stateToken": stateToken,
		"passCode":   auth.UserConfig.Passcode,
	}
	return auth.oktaReq(http.MethodPost, path, data)
}

// Cancel an authentication transaction
func (auth *OktaApiAuth) cancelAuth(stateToken string) {
	// https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
	log.Trace().Msg("oktaApiAuth.cancelAuth()")
	data := map[string]string{
		"stateToken": stateToken,
	}
	_, _, _ = auth.oktaReq(http.MethodPost, "/authn/cancel", data)
}

func processJsonAnswer(apiRes []byte, count int, nbFactors int) (AuthResponse, error) {
	var authRes AuthResponse
	err := json.Unmarshal(apiRes, &authRes)
	if err != nil {
		if count == nbFactors-1 {
			log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
			return AuthResponse{}, err
		}
		log.Warn().Msgf("Error unmarshaling Okta API response: %s", err)
		return AuthResponse{}, errContinue
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(authRes)
	if err != nil {
		if count == nbFactors-1 {
			log.Error().Msgf("Error unmarshaling Okta API response: %s", err)
			return AuthResponse{}, err
		}
		log.Warn().Msgf("Error unmarshaling Okta API response: %s", err)
		return AuthResponse{}, errContinue
	}
	return authRes, nil
}

func (auth *OktaApiAuth) doAuthFirstStep(factor AuthFactor, count int, nbFactors int, stateToken string, ftype string) (AuthResponse, error) {
	log.Trace().Msgf("oktaApiAuth.doAuthFirstStep() %s %s", factor.Type, factor.Provider)
	code, apiRes, err := auth.doAuth(factor.Id, stateToken)
	if err != nil {
		if count == nbFactors-1 {
			return AuthResponse{}, err
		}
		return AuthResponse{}, errContinue
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
			}
		} else {
			errorSummary = fmt.Sprintf("HTTP status code %d", code)
		}
		if count == nbFactors-1 {
			log.Error().Msgf("%s %s MFA authentication failed: %s",
				factor.Provider,
				ftype,
				errorSummary)
			ferror := fmt.Sprintf("%s MFA failed", ftype)
			return AuthResponse{}, errors.New(ferror)
		}
		log.Warn().Msgf("%s %s MFA authentication failed: %s",
			factor.Provider,
			ftype,
			errorSummary)
		return AuthResponse{}, errContinue
	}

	return processJsonAnswer(apiRes, count, nbFactors)
}

// At first iteration and until the factorResult is different from WAITING
// keep retrying the Push MFA (we are waiting here that the user either accept or reject auth)
func (auth *OktaApiAuth) waitForPush(factor AuthFactor, count int, nbFactors int, stateToken string) (authRes AuthResponse, err error) {
	log.Trace().Msgf("oktaApiAuth.waitForPush() %s %s", factor.Type, factor.Provider)
	checkCount := 0
	for checkCount == 0 || authRes.Result == "WAITING" {
		checkCount++
		if checkCount > auth.ApiConfig.MFAPushMaxRetries {
			if count == nbFactors-1 {
				log.Error().Msgf("%s push MFA timed out", factor.Provider)
				return AuthResponse{}, errors.New("Push MFA timeout")
			}
			log.Warn().Msgf("%s push MFA timed out", factor.Provider)
			return AuthResponse{}, errContinue
		}

		time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds) * time.Second)

		code, apiRes, err := auth.doAuth(factor.Id, stateToken)
		if err != nil {
			if count == nbFactors-1 {
				return AuthResponse{}, err
			}
			return AuthResponse{}, errContinue
		}
		if code != 200 && code != 202 {
			if count == nbFactors-1 {
				log.Error().Msgf("%s push MFA invalid HTTP status code %d", factor.Provider, code)
				return AuthResponse{}, errors.New("Push MFA failed")
			}
			log.Warn().Msgf("%s push MFA invalid HTTP status code %d", factor.Provider, code)
			return AuthResponse{}, errContinue
		}

		authRes, err = processJsonAnswer(apiRes, count, nbFactors)
		if err != nil {
			return authRes, err
		}
	}
	return authRes, nil
}
