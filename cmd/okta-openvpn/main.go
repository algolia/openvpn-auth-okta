package main

import (
  "flag"
  "fmt"
  "os"
  "regexp"

  "gopkg.in/algolia/okta-openvpn.v2/pkg/validator"
)

var debug *bool

type OktaOpenVPNValidator = validator.OktaOpenVPNValidator

func main() {
  debug = flag.Bool("d", false, "enable debugging")
	flag.Parse()
	args := flag.Args()
  if *debug {
    fmt.Println("DEBUG MODE")
  }

  oktaValidator := validator.NewOktaOpenVPNValidator()
  if err := oktaValidator.ReadConfigFile(); err != nil {
    os.Exit(1)
  }

  if len(args) > 0 {
    // We're running in "Script Plugins" mode with "via-file" method
    // see "--auth-user-pass-verify cmd method" in
    //   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
    if err := oktaValidator.LoadViaFile(args[0]); err != nil {
      os.Exit(1)
    }
  } else {
    // We're running in "Script Plugins" mode with "via-env" method
    // or in "Shared Object Plugin" mode
    // see https://openvpn.net/community-resources/using-alternative-authentication-methods/
    oktaValidator.LoadEnvVars()
  }
  /* OpenVPN doc says:
  To protect against a client passing a maliciously formed username or password string,
  the username string must consist only of these characters:
  alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
  */
  match, err := regexp.MatchString(`^([[:alpha:]]|[_\-\.@])*$`, oktaValidator.Username());
  if err != nil || !match {
    fmt.Println("Invalid username format")
    os.Exit(1)
  }

  if err := oktaValidator.LoadPinset(); err != nil {
    os.Exit(1)
  }
  oktaValidator.Authenticate()
  if oktaValidator.Mode() == validator.ViaEnv {
    oktaValidator.WriteControlFile()
  }
  if oktaValidator.IsUserValid() {
    os.Exit(0)
  }
  os.Exit(1)
}
