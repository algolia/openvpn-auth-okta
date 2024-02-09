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

// Computed with:
/*
echo -n | openssl s_client -connect example.oktapreview.com:443 2>/dev/null |\
 openssl x509 -noout -pubkey |\
 openssl rsa	-pubin -outform der 2>/dev/null |\
 openssl dgst -sha256 -binary | base64
*/
// used in api_test.go, oktaApiAuth_test.go, utils_test.go
var pin []string = []string{"SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="}

// used in api_test.go, oktaApiAuth_test.go, utils_test.go
type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}
