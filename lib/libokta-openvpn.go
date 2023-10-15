package main

import "C"

import (
  "gopkg.in/algolia/okta-openvpn.v2/pkg/validator"
)

//export Run
func Run() {
  v := validator.NewOktaOpenVPNValidator()
  if res := v.Setup(true, nil); !res {
    return
  }
  v.Authenticate()
  v.WriteControlFile()
}

func main() {
}
