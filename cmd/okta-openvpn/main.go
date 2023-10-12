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
  if err := oktaValidator.ReadConfigFile(); err != nil {
    if *deferred {
      /*
      * if invoked as a deferred plugin, we should always exit 0 and write result
      * in the control file.
      * here the validator control may not have been yet set, force it
      */
      oktaValidator.SetControlFile(os.Getenv("auth_control_file"))
      oktaValidator.WriteControlFile()
      os.Exit(0)
    }
    os.Exit(1)
  }

  if !*deferred {
    // We're running in "Script Plugins" mode with "via-env" method
    // see "--auth-user-pass-verify cmd method" in
    //   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
    if len(args) > 0 {
      // via-file" method
      if err := oktaValidator.LoadViaFile(args[0]); err != nil {
        os.Exit(1)
      }
    } else {
      // "via-env" method
      if err := oktaValidator.LoadEnvVars(); err != nil {
        os.Exit(1)
      }
    }
  } else {
    // We're running in "Shared Object Plugin" mode
    // see https://openvpn.net/community-resources/using-alternative-authentication-methods/
    if err := oktaValidator.LoadEnvVars(); err != nil {
      oktaValidator.WriteControlFile()
      os.Exit(0)
    }
  }

  if err := oktaValidator.LoadPinset(); err != nil {
    if *deferred {
      oktaValidator.WriteControlFile()
      os.Exit(0)
    }
    os.Exit(1)
  }
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
