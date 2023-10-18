package main

import "C"

import (
  "gopkg.in/algolia/okta-openvpn.v2/pkg/validator"
  "gopkg.in/algolia/okta-openvpn.v2/pkg/types"
)

type PluginEnv = types.PluginEnv

//export Run
func Run(ctrF *C.char, ip *C.char, cn *C.char, user *C.char, pass *C.char) {

  pluginEnv := &PluginEnv{
    Username: C.GoString(user),
    CommonName: C.GoString(cn),
    Password: C.GoString(pass),
    ClientIp: C.GoString(ip),
    ControlFile: C.GoString(ctrF),
  }

  v := validator.NewOktaOpenVPNValidator()
  if res := v.Setup(true, nil, pluginEnv); !res {
    return
  }
  v.Authenticate()
  v.WriteControlFile()
}

func main() {
}
