// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package duoAuthApi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	duoauth "github.com/duosecurity/duo_api_golang/authapi"
	"github.com/phuslu/log"
	"gopkg.in/algolia/openvpn-auth-okta.v3/pkg/authApi"
)

var errCheckFailed = errors.New("Duo check failed")

type ProviderApiConfig struct {
	// Your (company's) Duo Integartion key
	Ikey string

	// Your (company's) Duo Secret key
	Skey string

	Timeout int
}

type DuoAuthApi struct {
	ApiConfig      *authApi.APIConfig
	UserConfig     *authApi.APIUserConfig
	ProviderConfig *ProviderApiConfig
	pool           *http.Client
	duoApi         *duoauth.AuthApi
}

func New() *DuoAuthApi {
	return &DuoAuthApi{
		ApiConfig: &authApi.APIConfig{
			Provider:            "Duo",
			AllowUntrustedUsers: false,
			MFARequired:         false,
			TOTPFallbackToPush:  false,
		},
		UserConfig: &authApi.APIUserConfig{},
	}
}

func (auth *DuoAuthApi) GetApiConfig() *authApi.APIConfig {
	return auth.ApiConfig
}

func (auth *DuoAuthApi) GetUserConfig() *authApi.APIUserConfig {
	return auth.UserConfig
}

// Check if DUO endpoint is available and if config is OK
// by using PreAuth
func (auth *DuoAuthApi) preAuthDuo() (*duoauth.PreauthResult, error) {
	log.Trace().Msg("duoAuthApi.preAuthDuo()")
	log.Info().Msg("Running Duo PreAuth")
	// Prepare the pre auth request
	options := func(opts *url.Values) {
		opts.Set("username", auth.UserConfig.Username)
		if auth.UserConfig.ClientIp != "" {
			opts.Set("ipaddr", auth.UserConfig.ClientIp)
		}
	}
	preAuthResult, err := auth.duoApi.Preauth(options)
	if err != nil {
		log.Error().Msgf("Error connecting to the Duo Api: %s", err)
		return nil, err
	}

	if preAuthResult.Stat != "OK" {
		msg := fmt.Sprintf("error during Duo preAuth%s", getDuoResultErrorMsg(preAuthResult))
		log.Error().Msg(msg)
		return nil, errors.New(msg)
	}

	return preAuthResult, nil
}

func (auth *DuoAuthApi) authDevice(device string) error {
	log.Trace().Msg("duoAuthApi.authDevice()")
	options := func(opts *url.Values) {
		opts.Set("username", auth.UserConfig.Username)
		opts.Set("type", "OpenVPN authentication")
		opts.Set("device", device)
		if auth.UserConfig.ClientIp != "" {
			opts.Set("ipaddr", auth.UserConfig.ClientIp)
		}
	}

	log.Info().Msg("Running Push Duo Auth")
	authResult, err := auth.duoApi.Auth("push", options)
	if err != nil {
		log.Error().Msgf("error during Duo auth: %s", err)
		return fmt.Errorf("%s Push MFA authentication failed: %s, %w",
			device,
			err,
			authApi.ErrPushFailed)
	}

	if authResult.Stat != "OK" {
		msg := getDuoResultErrorMsg(authResult)
		log.Error().Msgf("error during Duo auth: %s", msg)
		return fmt.Errorf("%s Push MFA authentication failed: %s, %w",
			device,
			msg,
			authApi.ErrPushFailed)
	}

	if authResult.Response.Result == "allow" {
		log.Info().Msg("Access authorized")
		return nil
	}

	log.Error().Msgf("%s Push MFA authentication failed", device)
	return fmt.Errorf("%s Push MFA authentication denied, %w",
		device,
		authApi.ErrPushFailed)
}

func (auth *DuoAuthApi) authPasscode() error {
	log.Trace().Msg("duoAuthApi.authPasscode()")
	options := func(opts *url.Values) {
		opts.Set("username", auth.UserConfig.Username)
		opts.Set("passcode", auth.UserConfig.Passcode)
	}

	log.Info().Msg("Running TOTP Duo Auth")
	authResult, err := auth.duoApi.Auth("passcode", options)
	if err != nil {
		return fmt.Errorf("error during Duo auth: %w", err)
	}

	if authResult.Stat != "OK" {
		return fmt.Errorf("error during Duo auth%s", getDuoResultErrorMsg(authResult))
	}

	if authResult.Response.Result == "allow" {
		log.Info().Msg("Access authorized")
		return nil
	}
	return authApi.ErrTOTPFailed
}

func (auth *DuoAuthApi) verifyPushFactors(preAuthRes *duoauth.PreauthResult) (err error) {
	log.Trace().Msg("duoAuthApi.verifyPushFactors()")
	nbDevices := len(preAuthRes.Response.Devices)
	// Send push notification to first capable device
	for count, device := range preAuthRes.Response.Devices {
		for _, capa := range device.Capabilities {
			if capa == "push" || capa == "auto" {
				log.Debug().Msgf("Trying to authenticate with %s", device.Device)

				if err = authApi.ParseError(auth.authDevice(device.Device), count, nbDevices); err != nil {
					return err
				}
			}
		}
	}
	// Reached only when the list of factors provided is empty
	log.Debug().Msg("No Push MFA available")
	return authApi.ErrMFAUnavailable
}

// Gather the list of factors available from the pre authentication api response,
// if the user provided a TOTP in its passwordd string, try TOTP MFA
// otherwise try Push MFA
func (auth *DuoAuthApi) validateUserMFA(preAuthRes *duoauth.PreauthResult) (err error) {
	log.Trace().Msg("duoAuthApi.validateUserMFA()")

	if auth.UserConfig.Passcode != "" {
		if err = auth.authPasscode(); err != nil {
			if auth.ApiConfig.TOTPFallbackToPush {
				// If TOTP auth failed and fallback to push has been enabled in config
				// try Push MFA authentication
				goto PUSH
			}
			return err
		}
		return nil
	}

PUSH:
	if err = auth.verifyPushFactors(preAuthRes); err != nil {
		return err
	}
	return nil
}

// AuthDuoPush: This public method query the DUO endpoint with user information
// to request a push notifications on the first available user device.
func (auth *DuoAuthApi) Auth() error {
	log.Trace().Msg("duoAuthApi.Auth()")
	log.Info().Msgf("Authenticating")

	if res, err := auth.duoApi.Check(); err != nil || res.Stat != "OK" {
		return errCheckFailed
	}

	// Check DUO preauth and get result
	preAuthResult, err := auth.preAuthDuo()
	if err != nil {
		return err
	}

	switch preAuthResult.Response.Result {
	case "allow":
		if auth.ApiConfig.MFARequired {
			log.Error().Msg("error during Duo preAuth: allowed but MFA is required")
			return authApi.ErrMFARequired
		}
		return nil

	case "auth":
		return auth.validateUserMFA(preAuthResult)

	case "deny":
		log.Error().Msg("error during Duo preAuth: denied")
		return errors.New("error during Duo preAuth: denied")

	case "enroll":
		log.Error().Msg("error during Duo preAuth: user needs to enroll MFA")
		return authApi.ErrEnrollNeeded

	default:
		log.Error().Msgf("unknown Duo preauth status: %s", preAuthResult.Response.Result)
		return authApi.ErrPreauthUnknownStatus
	}
}
