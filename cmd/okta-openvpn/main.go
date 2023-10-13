package main

import (
  "flag"
  "fmt"
  "os"

  "gopkg.in/algolia/okta-openvpn.v2/pkg/validator"
)

var (
  debug    *bool
  deferred *bool
)

type OktaOpenVPNValidator = validator.OktaOpenVPNValidator

func main() {
  debug = flag.Bool("d", false, "enable debugging")
  deferred = flag.Bool("deferred", false, "does this run as a deferred OpenVPN plugin")
  flag.Parse()
  args := flag.Args()
  if *debug {
    fmt.Println("DEBUG MODE")
    if *deferred {
      fmt.Println("Running as a Shared Object deferred plugin")
    } else {
      fmt.Println("Running as a Script plugin")
    }
  }

  oktaValidator := validator.NewOktaOpenVPNValidator()
  oktaValidator.Setup(*deferred, args)
  oktaValidator.Authenticate()
  if *deferred {
    oktaValidator.WriteControlFile()
    os.Exit(0)
  }
  // from here, in "Script Plugins" mode
  if oktaValidator.IsUserValid() {
    os.Exit(0)
  }
  os.Exit(1)
}
