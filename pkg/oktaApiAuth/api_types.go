// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2024-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oktaApiAuth

type ErrorResponse struct {
	Code    string        `json:"errorCode" validate:"required"`
	Summary string        `json:"errorSummary" validate:"required"`
	Link    string        `json:"errorLink" validate:"required"`
	Id      string        `json:"errorId" validate:"required"`
	Causes  []ErrorCauses `json:"errorCauses" validate:"required"`
}

type ErrorCauses struct {
	Summary string `json:"errorSummary"`
}

type PreAuthResponse struct {
	Token    string          `json:"stateToken"`
	Status   string          `json:"status" validate:"required"`
	Embedded PreAuthEmbedded `json:"_embedded"`
}

type PreAuthEmbedded struct {
	Factors []AuthFactor `json:"factors"`
}

type AuthFactor struct {
	Id       string `json:"id" validate:"required"`
	Type     string `json:"factorType" validate:"required"`
	Provider string `json:"provider" validate:"required"`
}

type AuthResponse struct {
	Token  string `json:"stateToken"`
	Status string `json:"status"`
	Result string `json:"factorResult"`
}

/*
	type GroupResponse struct {
		Groups []OktaGroup
	}
*/
type OktaGroup struct {
	Id      string           `json:"id"`
	Profile OktaGroupProfile `json:"profile"`
}

type OktaGroupProfile struct {
	Name string `json:"name"`
}
