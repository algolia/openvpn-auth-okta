package main

import "C"

import (
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
)

type PluginEnv = validator.PluginEnv

//export OktaAuthValidator
func OktaAuthValidator(ctrF *C.char, ip *C.char, cn *C.char, user *C.char, pass *C.char) {
	// TODO: find an elegant way to pass a const char** from C plugin
	pluginEnv := &PluginEnv{
		Username:    C.GoString(user),
		CommonName:  C.GoString(cn),
		Password:    C.GoString(pass),
		ClientIp:    C.GoString(ip),
		ControlFile: C.GoString(ctrF),
	}

	v := validator.NewOktaOpenVPNValidator()
	if res := v.Setup(true, false, nil, pluginEnv); !res {
		return
	}
	_ = v.Authenticate()
	v.WriteControlFile()
}

func main() {
}
