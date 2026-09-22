// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*
CLI tool to test/request Okta MFA validation
*/
package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
)

var (
	debug    *bool
	deferred *bool
)

type OktaOpenVPNValidator = validator.OktaOpenVPNValidator

func init() {
	// Add detailed help text
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `OpenVPN Okta Authentication Validator

This tool authenticates OpenVPN users against Okta's Authentication API with MFA support.

Usage:
    okta-auth-validator [flags] [arguments]

Flags:
    -d, --debug        Enable debug logging
    -dd, --trace       Enable trace logging (very verbose)
    -deferred          Run in deferred plugin mode (default: script mode)
    -h, --help         Show this help message

Examples:
    # Script plugin mode (via-env)
    okta-auth-validator

    # Script plugin mode (via-file)
    okta-auth-validator /path/to/via-file

    # Deferred plugin mode
    okta-auth-validator -deferred

Environment Variables:
    AUTH_CONTROL_FILE   Path to OpenVPN control file
    UNTRUSTED_IP        Client IP address
    COMMON_NAME         Certificate common name
    USERNAME            User identifier
    PASSWORD            User password

Configuration:
    Default config files are looked for in:
    - /etc/okta-auth-validator/api.ini
    - /etc/openvpn/okta_openvpn.ini
    - /etc/okta_openvpn.ini
    - api.ini
    - okta_openvpn.ini

    Default pinset files are looked for in:
    - /etc/okta-auth-validator/pinset.cfg
    - /etc/openvpn/okta_pinset.cfg
    - /etc/okta_pinset.cfg
    - pinset.cfg
    - okta_pinset.cfg

Exit Codes:
    0   Success - authentication passed
    1   Failure - authentication failed
    2   Configuration error
    3   Internal error
`)
	}
}

func main() {
	logLevel := "INFO"
	debug = flag.Bool("d", false, "enable debugging")
	trace := flag.Bool("dd", false, "enable heavy debugging")
	deferred = flag.Bool("deferred", false, "does this run as a deferred OpenVPN plugin")
	flag.Parse()
	args := flag.Args()

	if *debug {
		logLevel = "DEBUG"
	}
	if *trace {
		logLevel = "TRACE"
	}

	oktaValidator := validator.New(logLevel)
	if res := oktaValidator.Setup(*deferred, args, nil); !res {
		if *deferred {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	err := oktaValidator.Authenticate()
	if *deferred {
		oktaValidator.WriteControlFile()
		os.Exit(0)
	}
	// from here, in "Script Plugins" mode
	if err == nil {
		os.Exit(0)
	}
	os.Exit(1)
}
