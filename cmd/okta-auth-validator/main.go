package main

import (
	"flag"
	"os"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
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

	oktaValidator := validator.NewOktaOpenVPNValidator()
	if res := oktaValidator.Setup(*deferred, *debug, args, nil); !res {
		if *deferred {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	err := oktaValidator.Authenticate()
	if *deferred {
		oktaValidator.WriteControlFile()
		os.Exit(0)
	}
	// from here, in "Script Plugins" mode
	if err == nil {
		os.Exit(0)
	}
	os.Exit(1)
}
