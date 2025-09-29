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
	"fmt"

	duoauth "github.com/duosecurity/duo_api_golang/authapi"
)

func getDuoResultErrorMsg(result interface{}) string {
	var stat string
	var status_msg string

	switch r := result.(type) {
	case (*duoauth.PreauthResult):
		stat = r.Stat
		status_msg = r.Response.Status_Msg
	case (*duoauth.AuthResult):
		stat = r.Stat
		status_msg = r.Response.Status_Msg
	default:
		return ": unknown response type"
	}

	if status_msg != "" {
		return fmt.Sprintf(": %s", status_msg)
	}
	if stat != "" {
		return fmt.Sprintf(", stat: %s", stat)
	}
	return ": unknown stat"
}
