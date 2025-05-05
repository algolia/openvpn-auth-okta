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

	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

func TestParseConfig(t *testing.T) {
	t.Run("Parse valid duo config", func(t *testing.T) {
		a := New()
		cfg, _ := ini.Load("../../testing/fixtures/validator/valid-duo.ini")
		err := a.ParseConfig(cfg)
		assert.Nil(t, err)
	})
}
