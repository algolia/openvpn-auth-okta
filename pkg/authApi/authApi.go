// SPDX-FileCopyrightText: 2025-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2025-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package authApi

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/phuslu/log"
	"gopkg.in/ini.v1"
)

// Contains the configuration for the Okta API connection
// Those configuration options are read from api.ini
type APIConfig struct {
	// For now, should be either Duo or Okta
	Provider string

	// auth API server url, ie https://example.oktapreview.com
	Url string

	// The suffix to be added to your users names:
	// ie if UsernameSuffix = "example.com" and your user logs in with "dade.murphy"
	// the validator will try to authenticate for "dade.murphy@example.com"
	UsernameSuffix string

	// A list of valid SSL public key fingerprint to validate the auth API server certificate against
	AssertPin []string

	// Is MFA Required for all users. If yes and Okta authenticates the user without MFA (not configured)
	// the validator will reject it.
	MFARequired bool // default: false

	// Do not require usernames to come from client-side SSL certificates
	AllowUntrustedUsers bool // default: false

	// If a passcode is provided and TOTP MFA fails, try Push MFA
	TOTPFallbackToPush bool // default: false
}

// User credentials and informations
type APIUserConfig struct {
	Username string
	Password string
	Passcode string
	ClientIp string
}

type AuthApi interface {
	Setup() error
	GetUserConfig() *APIUserConfig
	GetApiConfig() *APIConfig
	ParseConfig(cfg *ini.File) error
	Auth() error
}

// Prepare an http client with a safe TLS config
// validate the server public key against our list of pinned key fingerprint
func ApiInitPool(cfg *APIConfig) (*http.Client, error) {
	log.Trace().Msg("authApi.ApiInitPool()")
	if rawURL, err := url.Parse(cfg.Url); err != nil {
		return nil, err
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
			return nil, err
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			if !cert.IsCA {
				// Compute public key base64 digest
				derPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return nil, err
				}
				pubKeySha := sha256.Sum256(derPubKey)
				digest := base64.StdEncoding.EncodeToString([]byte(string(pubKeySha[:])))

				if !slices.Contains(cfg.AssertPin, digest) {
					log.Error().Msgf("Refusing to authenticate because host %s failed %s\n%s\n%s",
						rawURL.Hostname(),
						"a TLS public key pinning check.",
						"Update your \"pinset.cfg\" file or ",
						"contact support@okta.com with this error message")
					return nil, errors.New("Server pubkey does not match pinned keys")
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

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: t,
	}, nil
}

// ParseError will depending on the fact that the current factor
// is the last one either return the unrapped original error or nil
// and log (error level for the last one, otherwise warn level)
func ParseError(err error, count int, nbFactors int) error {
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
