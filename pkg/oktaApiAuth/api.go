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

// InitPool initializes the HTTP client with TLS certificate pinning.
//
// This is a critical security function that prevents man-in-the-middle attacks
// by validating Okta's TLS certificate against known public key fingerprints.
//
// TLS pinning process:
//  1. Connects to Okta server (with InsecureSkipVerify temporarily)
//  2. Retrieves peer certificates from TLS handshake
//  3. For each non-CA certificate:
//     - Marshals public key to DER format
//     - Computes SHA256 hash of public key
//     - Base64 encodes the hash
//     - Verifies digest exists in ApiConfig.AssertPin
//  4. If no pinned key matches, returns error and refuses connection
//  5. If validated, creates secure HTTP client with:
//     - TLS 1.2+ minimum version
//     - Strong cipher suites only
//     - Proper certificate verification enabled
//     - 10-second timeout
//     - Connection pooling (max 5 connections)
//
// The pinned fingerprints must be loaded into ApiConfig.AssertPin before
// calling this function (typically from pinset.cfg).
//
// Security notes:
//   - NEVER bypass this function in production
//   - Update pinset.cfg when Okta rotates certificates
//   - Initial connection uses InsecureSkipVerify ONLY to extract the
//     certificate for validation - actual client uses full verification
//   - Tests use gock to intercept HTTP before TLS, avoiding real pinning
//
// Returns:
//   - nil: HTTP client initialized successfully, TLS pinning validated
//   - error: URL parsing failed, connection failed, or pinning check failed
//
// After successful initialization, auth.pool is ready for API requests.
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
		defer func() { _ = conn.Close() }()
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
					return errors.New("server pubkey does not match pinned keys")
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
// nolint:unused
func (auth *OktaApiAuth) getPool() *http.Client {
	return auth.pool
}

// oktaReq executes an HTTP request to the Okta API with proper authentication and headers.
//
// This is the low-level function for all Okta API communication. It handles:
//   - URL construction (base URL + API path)
//   - SSWS token authentication
//   - Standard headers (User-Agent, Accept, Content-Type)
//   - X-Forwarded-For header (if ClientIp configured)
//   - JSON payload marshalling (for POST requests)
//   - Response body reading
//
// Headers set:
//   - Authorization: SSWS {token}
//   - Content-Type: application/json
//   - Accept: application/json
//   - User-Agent: Chrome browser identifier (reduces rate limiting)
//   - X-Forwarded-For: Client IP (for audit trails)
//   - Sec-Ch-Ua-*: Browser security headers
//
// Parameters:
//   - method: HTTP method (http.MethodGet or http.MethodPost)
//   - path: API endpoint path relative to /api/v1 (e.g., "/authn")
//   - data: Request payload as map (marshalled to JSON for POST, ignored for GET)
//
// Returns:
//   - code: HTTP status code (200, 202, 400, 401, etc.)
//   - jsonBody: Response body as bytes (may be empty)
//   - err: Network error, marshalling error, or read error
//
// Note: Does not validate response status - caller must check code.
func (auth *OktaApiAuth) oktaReq(method string, path string, data map[string]string) (code int, jsonBody []byte, err error) {
	u, _ := url.ParseRequestURI(auth.ApiConfig.Url)
	u.Path = fmt.Sprintf("/api/v1%s", path)

	userAgent := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 (OktaOpenVPN)"
	ssws := fmt.Sprintf("SSWS %s", auth.ApiConfig.Token)

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
	defer func() { _ = resp.Body.Close() }()
	jsonBody, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msgf("Error reading Okta API response: %s", err)
		return 0, nil, err
	}

	return resp.StatusCode, jsonBody, nil
}

// preAuth calls Okta's primary authentication endpoint.
//
// Submits username and password to initiate authentication flow.
// This is always the first API call in the authentication sequence.
//
// API endpoint: POST /api/v1/authn
// See: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
//
// Request payload:
//
//	{
//	  "username": "user@example.com",
//	  "password": "userPassword123"
//	}
//
// Returns:
//   - code: HTTP status code (200=success, 401=invalid credentials, etc.)
//   - body: JSON response body (PreAuthResponse when successful)
//   - err: Network or request error
func (auth *OktaApiAuth) preAuth() (int, []byte, error) {
	// https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
	log.Trace().Msg("oktaApiAuth.preAuth()")
	data := map[string]string{
		"username": auth.UserConfig.Username,
		"password": auth.UserConfig.Password,
	}
	return auth.oktaReq(http.MethodPost, "/authn", data)
}

// doAuth verifies an MFA factor.
//
// Submits factor verification request to Okta API.
// For TOTP: includes passcode for immediate verification.
// For Push: initiates push notification to user's device.
//
// API endpoint: POST /api/v1/authn/factors/{fid}/verify
// See: https://developer.okta.com/docs/reference/api/authn/#verify-factor
//
// Request payload:
//
//	{
//	  "fid": "factorId",
//	  "stateToken": "transactionToken",
//	  "passCode": "123456"  // for TOTP, empty for Push
//	}
//
// Parameters:
//   - fid: Factor ID to verify (from PreAuthResponse.Embedded.Factors)
//   - stateToken: Authentication transaction token
//
// Returns:
//   - code: HTTP status code
//   - body: JSON response (AuthResponse)
//   - err: Network or request error
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

// cancelAuth terminates an in-progress authentication transaction.
//
// Should be called when:
//   - MFA verification fails
//   - User is in invalid state (locked, needs enrollment, etc.)
//   - Any error occurs during authentication flow
//
// Prevents abandoned transactions from accumulating in Okta.
// Errors during cancellation are intentionally ignored (best-effort).
//
// API endpoint: POST /api/v1/authn/cancel
// See: https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
//
// Parameters:
//   - stateToken: Transaction token to cancel
func (auth *OktaApiAuth) cancelAuth(stateToken string) {
	// https://developer.okta.com/docs/reference/api/authn/#cancel-transaction
	log.Trace().Msg("oktaApiAuth.cancelAuth()")
	data := map[string]string{
		"stateToken": stateToken,
	}
	_, _, _ = auth.oktaReq(http.MethodPost, "/authn/cancel", data)
}

// parseAuthResponse unmarshals and validates an MFA verification response.
//
// Parses JSON response from doAuth() into AuthResponse struct and validates
// that all required fields are present using struct tags.
//
// Validation ensures:
//   - Status field is present (required)
//   - Response structure matches expected format
//   - No critical fields are missing
//
// Parameters:
//   - apiRes: Raw JSON response body from doAuth()
//
// Returns:
//   - AuthResponse: Parsed and validated response
//   - error: JSON unmarshalling failed or validation failed
func parseAuthResponse(apiRes []byte) (AuthResponse, error) {
	var authRes AuthResponse
	err := json.Unmarshal(apiRes, &authRes)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error unmarshaling Okta API response: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(authRes)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error unmarshaling Okta API response: %w", err)
	}
	return authRes, nil
}

// parseOktaError implements smart error handling for multi-factor authentication.
//
// When attempting multiple factors sequentially, we don't want to fail on the
// first error - we should try remaining factors. This function:
//   - Suppresses errors for non-final factors (logs as warning)
//   - Returns unwrapped error for final factor (logs as error)
//   - Returns nil for non-final factors to continue iteration
//
// This enables graceful degradation:
//   - User has 3 TOTP factors configured
//   - First two fail (wrong app, expired code, etc.)
//   - Third succeeds -> authentication successful
//
// Without this logic, we'd fail on the first invalid factor.
//
// Parameters:
//   - err: Error from factor verification attempt
//   - count: Current factor index (0-based)
//   - nbFactors: Total number of factors being attempted
//
// Returns:
//   - nil: Non-final factor failed (continue trying)
//   - error: Final factor failed (return to caller)
func parseOktaError(err error, count int, nbFactors int) error {
	if err != nil {
		if count == nbFactors-1 {
			log.Error().Msgf("%s", err.Error())
			if err2 := errors.Unwrap(err); err2 != nil {
				return fmt.Errorf("%s", err2)
			} else {
				return fmt.Errorf("%s", err)
			}
		}
		log.Warn().Msgf("%s", err.Error())
		return nil
	}
	return nil
}

// doAuthFirstStep performs initial MFA factor verification.
//
// Submits factor verification request and parses the response.
// Handles both TOTP and Push factor types.
//
// For TOTP:
//   - Immediately returns success or failure based on passcode
//
// For Push:
//   - Returns Result="WAITING" to indicate notification sent
//   - Caller must poll with waitForPush() for final result
//
// Error handling:
//   - Checks HTTP status code (200/202 = success)
//   - Parses Okta error responses for detailed error messages
//   - Extracts error summary from causes or main summary
//   - Wraps errors with factor and provider information
//
// Parameters:
//   - factor: MFA factor to verify
//   - stateToken: Authentication transaction token
//   - ftype: Factor type string ("TOTP" or "Push" for logging)
//
// Returns:
//   - AuthResponse: Verification result (may be WAITING for Push)
//   - error: API error, network error, or verification failed
func (auth *OktaApiAuth) doAuthFirstStep(factor AuthFactor, stateToken string, ftype string) (AuthResponse, error) {
	log.Trace().Msgf("oktaApiAuth.doAuthFirstStep() %s %s", factor.Type, factor.Provider)
	code, apiRes, err := auth.doAuth(factor.Id, stateToken)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("okta authentication request error: %w", err)
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

// waitForPush polls Okta API until Push MFA is approved, rejected, or times out.
//
// After sending a Push notification, Okta returns Result="WAITING".
// This function polls the same factor verification endpoint repeatedly
// until the user responds or maximum retries is reached.
//
// Polling behavior:
//   - Waits MFAPushDelaySeconds between each poll
//   - Continues while Result="WAITING"
//   - Stops on Result="SUCCESS", "REJECTED", "TIMEOUT", or error
//   - Fails after MFAPushMaxRetries attempts
//
// Timeout calculation:
//
//	Total wait = MFAPushMaxRetries × MFAPushDelaySeconds
//	Default: 20 × 3 = 60 seconds
//
// User experience:
//   - User receives push notification on phone
//   - Approves or rejects within timeout window
//   - Server polls in background until response received
//
// Parameters:
//   - factor: Push factor being verified
//   - count: Factor index in list (for error handling)
//   - nbFactors: Total factors being tried (for error handling)
//   - stateToken: Authentication transaction token
//
// Returns:
//   - AuthResponse: Final verification result
//   - error: Timeout, rejection, or API error
func (auth *OktaApiAuth) waitForPush(factor AuthFactor, count int, nbFactors int, stateToken string) (authRes AuthResponse, err error) {
	log.Trace().Msgf("oktaApiAuth.waitForPush() %s %s", factor.Type, factor.Provider)

	for checkCount := 0; checkCount == 0 || authRes.Result == "WAITING"; checkCount++ {
		if checkCount >= auth.ApiConfig.MFAPushMaxRetries {
			return AuthResponse{}, fmt.Errorf("%s %w", factor.Provider, errors.New("push MFA timeout"))
		}

		time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds) * time.Second)

		code, apiRes, err := auth.doAuth(factor.Id, stateToken)
		if err != nil {
			return AuthResponse{}, fmt.Errorf("okta authentication request error: %w", err)
		}
		if code != 200 && code != 202 {
			return AuthResponse{}, fmt.Errorf("%s push MFA invalid HTTP status code %d, %w",
				factor.Provider,
				code,
				errors.New("push MFA failed"))
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
