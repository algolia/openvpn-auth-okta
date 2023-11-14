package main

import "C"

import (
	"time"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
	log "github.com/sirupsen/logrus"
	"github.com/t-tomalak/logrus-easy-formatter"
)

type PluginEnv = validator.PluginEnv

//export OktaAuthValidator
func OktaAuthValidator(ctrF *C.char, ip *C.char, cn *C.char, user *C.char, pass *C.char) {
	log.SetFormatter(&easy.Formatter{
		TimestampFormat: time.ANSIC,
		LogFormat: "%time% [okta-auth-validator](%lvl%): %msg%\n",
	})

	pluginEnv := &PluginEnv{
		Username:    C.GoString(user),
		CommonName:  C.GoString(cn),
		Password:    C.GoString(pass),
		ClientIp:    C.GoString(ip),
		ControlFile: C.GoString(ctrF),
	}

	v := validator.NewOktaOpenVPNValidator()
	if res := v.Setup(true, nil, pluginEnv); !res {
		return
	}
	_ = v.Authenticate()
	v.WriteControlFile()
}

func main() {
}
