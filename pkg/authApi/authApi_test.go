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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type errorTest struct {
	testName    string
	inputErrMsg string
	inputErr2   error
	count       int
	errMsg      string
}

func TestParseOktaError(t *testing.T) {
	nonWrappedLast := "non-wrapped error for last factor"
	nonWrapped := "non-wrapped error for first factor"
	tests := []errorTest{
		{
			"Test non-wrapped error for last factor",
			nonWrappedLast,
			nil,
			1,
			nonWrappedLast,
		},
		{
			"Test non-wrapped error for non-last factor",
			nonWrapped,
			nil,
			0,
			"",
		},
		{
			"Test wrapped error for last factor",
			nonWrappedLast,
			fmt.Errorf("ERROR"),
			1,
			"ERROR",
		},
		{
			"Test wrapped error for non-last factor",
			nonWrapped,
			fmt.Errorf("ERROR"),
			0,
			"",
		},
		{
			"Test no Error",
			"",
			nil,
			1,
			"",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			var inputErr error
			if test.inputErrMsg != "" {
				if test.inputErr2 != nil {
					inputErr = fmt.Errorf("%s %w", test.inputErrMsg, test.inputErr2)
				} else {
					inputErr = fmt.Errorf("%s", test.inputErrMsg)
				}
			}
			err := ParseError(inputErr, test.count, 2)
			if test.errMsg == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.EqualError(t, err, test.errMsg)
				}
			}
		})
	}
}
