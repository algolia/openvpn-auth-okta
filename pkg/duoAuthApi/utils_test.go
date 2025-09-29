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
	"testing"

	duoapi "github.com/duosecurity/duo_api_golang"
	duoauth "github.com/duosecurity/duo_api_golang/authapi"
	"github.com/stretchr/testify/assert"
)

var (
	PREAUTH bool = false
	AUTH    bool = true
)

type duoResponse struct {
	Stat   string
	Msg    string
	Result string
}

func TestGetDuoResultErrorMsg(t *testing.T) {
	for _, testResp := range []duoResponse{
		{
			"",
			"",
			": unknown stat",
		},
		{
			"FAIL",
			"",
			", stat: FAIL",
		},
		{
			"",
			"FAILURE",
			": FAILURE",
		},
	} {
		d := &duoauth.AuthResult{
			StatResult: duoapi.StatResult{
				Stat: testResp.Stat,
			},
		}
		d.Response.Status_Msg = testResp.Msg
		assert.Equal(t, testResp.Result, getDuoResultErrorMsg(d))
	}
	assert.Equal(t, ": unknown response type", getDuoResultErrorMsg(""))
}
