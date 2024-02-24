// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import "C"

import (
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
)

type PluginEnv = validator.PluginEnv

//export OktaAuthValidator
func OktaAuthValidator(ctrF *C.char, ip *C.char, cn *C.char, user *C.char, pass *C.char) {
	// TODO: find an elegant way to pass a const char** from C plugin
	pluginEnv := &PluginEnv{
		Username:    C.GoString(user),
		CommonName:  C.GoString(cn),
		Password:    C.GoString(pass),
		ClientIp:    C.GoString(ip),
		ControlFile: C.GoString(ctrF),
	}

	v := validator.NewOktaOpenVPNValidator()
	if res := v.Setup(true, nil, pluginEnv); !res {
		return
	}
	_ = v.Authenticate()
	v.WriteControlFile()
}

func main() {
}
