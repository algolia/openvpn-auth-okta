package oktaApiAuth

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (auth *OktaApiAuth) checkAllowedGroups() error {
	// https://developer.okta.com/docs/reference/api/users/#request-parameters-8
	if auth.ApiConfig.AllowedGroups != "" {
		groupRes, err := auth.oktaReq(http.MethodGet, fmt.Sprintf("/users/%s/groups", auth.UserConfig.Username), nil)
		if err != nil {
			return err
		}
		var aGroups []string = strings.Split(auth.ApiConfig.AllowedGroups, ",")
		for _, uGroup := range groupRes["data"].([]interface{}) {
			gName := uGroup.(map[string]interface{})["profile"].(map[string]interface{})["name"].(string)
			if slices.Contains(aGroups, gName) {
				log.Debugf("is a member of AllowedGroup %s", gName)
				return nil
			}
		}
		return errors.New("Not mmember of an AllowedGroup")
	}
	return nil
}

func (auth *OktaApiAuth) getUserFactors(preAuthRes map[string]interface{}) (factorsTOTP []interface{}, factorsPush []interface{}) {
	factors := preAuthRes["_embedded"].(map[string]interface{})["factors"].([]interface{})

	for _, f := range factors {
		factorType := f.(map[string]interface{})["factorType"].(string)
		if factorType == "token:software:totp" {
			if auth.UserConfig.Passcode != "" {
				factorsTOTP = append(factorsTOTP, f)
			}
		} else if factorType == "push" {
			factorsPush = append(factorsPush, f)
		} else {
			log.Debugf("unsupported factortype: %s, skipping", factorType)
		}
	}
	return
}

func (auth *OktaApiAuth) preChecks() (map[string]interface{}, error) {
	err := auth.checkAllowedGroups()
	if err != nil {
		log.Errorf("allowed group verification error: %s", err)
		return nil, err
	}

	preAuthRes, err := auth.preAuth()
	if err != nil {
		log.Errorf("Error connecting to the Okta API: %s", err)
		return nil, err
	}

	if _, ok := preAuthRes["errorCauses"]; ok {
		log.Warningf("pre-authentication failed: %s", preAuthRes["errorSummary"])
		return nil, errors.New("pre-authentication failed")
	}
	return preAuthRes, nil
}

func getToken(preAuthRes map[string]interface{}) (st string) {
	if tok, ok := preAuthRes["stateToken"]; ok {
		st = tok.(string)
	}
	return st
}
