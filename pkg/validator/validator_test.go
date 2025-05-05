// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validator

import (
	"io/fs"
	"os"
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/assert"
)

func TestWriteControlFile(t *testing.T) {
	tests := []testWriteFile{
		{
			"Test valid user - success",
			true,
			"1",
		},
		{
			"Test invalid user - success",
			false,
			"0",
		},
		{
			"Test non writable control file - success",
			false,
			"",
		},
	}
	var mode fs.FileMode
	for _, test := range tests {
		_, _ = os.Create(controlFile)
		defer func() { _ = os.Remove(controlFile) }()
		if test.expected == "" {
			mode = 0660
		} else {
			mode = 0600
		}
		_ = os.Chmod(controlFile, mode)
		t.Run(test.testName, func(t *testing.T) {
			v := New()
			v.controlFile = controlFile
			v.isUserValid = test.userValid
			v.WriteControlFile()
			ctrlValue, _ := os.ReadFile(controlFile)
			if test.expected == "" {
				i, _ := os.Stat(controlFile)
				size := i.Size()
				assert.Equal(t, size, int64(0))
			} else {
				assert.Equal(t, test.expected, string(ctrlValue))
			}
		})
	}
}
