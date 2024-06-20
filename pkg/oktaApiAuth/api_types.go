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

import "errors"

var (
	errContinue = errors.New("continue")
	errPushFailed = errors.New("Push MFA failed")
	errTOTPFailed = errors.New("TOTP MFA failed")
	errMFAUnavailable = errors.New("No MFA factor available")
	errMFARequired = errors.New("MFA required")
	errUserLocked = errors.New("User locked out")
	errPasswordExpired = errors.New("User password expired")
	errEnrollNeeded = errors.New("Needs to enroll")
)

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
	Status   string          `json:"status" validate:"required"`
	Token    string          `json:"stateToken"`
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
	Status string `json:"status" validate:"required"`
	Token  string `json:"stateToken"`
	Result string `json:"factorResult"`
}

type OktaGroups struct {
	Groups []OktaGroup `json:"groups" validate:"omitempty,dive"`
}

type OktaGroup struct {
	Id      string           `json:"id" validate:"required"`
	Profile OktaGroupProfile `json:"profile" validate:"required"`
}

type OktaGroupProfile struct {
	Name string `json:"name" validate:"required"`
}
