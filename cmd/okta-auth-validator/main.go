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
	"os"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
)

var (
	debug    *bool
	deferred *bool
)

type OktaOpenVPNValidator = validator.OktaOpenVPNValidator

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
