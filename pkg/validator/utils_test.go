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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

type usernameTest struct {
	testName string
	username string
	res      bool
}

type testControlFile struct {
	testName string
	path     string
	mode     fs.FileMode
	err      error
}

func TestCheckUsernameFormat(t *testing.T) {
	tests := []usernameTest{
		{
			"Valid username - success",
			"dade.murphy@example.com",
			true,
		},
		{
			"Invalid username - failure",
			"dade.*murphy/",
			false,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			res := checkUsernameFormat(test.username)
			assert.Equal(t, test.res, res)
		})
	}
}

func TestCheckNotWritable(t *testing.T) {
	t.Run("File does not exist - false", func(t *testing.T) {
		res := checkNotWritable("MISSING")
		assert.False(t, res)
	})
}

func TestGetEnv(t *testing.T) {
	t.Run("Env var does not exist - falback", func(t *testing.T) {
		res := getEnv("THIS_ENV_VER_DOES_NOT_EXIST", "value")
		assert.Equal(t, res, "value")
	})
	t.Run("Env var is empty - falback", func(t *testing.T) {
		_ = os.Setenv("THIS_ENV_VAR_IS_EMPTY", "")
		res := getEnv("THIS_ENV_VAR_IS_EMPTY", "value")
		_ = os.Unsetenv("THIS_ENV_VAR_IS_EMPTY")
		assert.Equal(t, res, "value")
	})
}

func TestCheckControlFilePerm(t *testing.T) {
	tests := []testControlFile{
		{
			"Test empty control file path - failure",
			"",
			0600,
			fmt.Errorf("Unknow control file"),
		},
		{
			"Test valid control file permissions - success",
			"../../testing/fixtures/validator/valid_control_file",
			0600,
			nil,
		},
		{
			"Test invalid control file permissions - success",
			"../../testing/fixtures/validator/invalid_control_file",
			0660,
			fmt.Errorf("control file writable by non-owners"),
		},
		{
			"Test invalid control file dir permissions - success",
			"../../testing/fixtures/validator/invalid_ctrlfile_dir_perm/ctrl",
			0600,
			fmt.Errorf("control file dir writable by non-owners"),
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			if test.path != "" {
				v.controlFile = test.path
				_, _ = os.Create(test.path)
				defer func() { _ = os.Remove(test.path) }()
				// This is crapy but git does not group write bit ...
				if dirName := filepath.Base(filepath.Dir(test.path)); dirName == "invalid_ctrlfile_dir_perm" {
					_ = os.Chmod(filepath.Dir(test.path), 0770)
				}
				_ = os.Chmod(test.path, test.mode)
			}
			err := v.checkControlFilePerm()
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
