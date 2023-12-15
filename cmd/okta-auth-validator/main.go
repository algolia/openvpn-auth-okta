package main

import (
	"flag"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/t-tomalak/logrus-easy-formatter"
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
	log.SetFormatter(&easy.Formatter{
		TimestampFormat: time.ANSIC,
		LogFormat:       "%time% [okta-auth-validator](%lvl%): %msg%\n",
	})
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if *deferred {
		log.Debug("Running as a Shared Object deferred plugin")
	} else {
		log.Debug("Running as a Script plugin")
	}

	oktaValidator := validator.NewOktaOpenVPNValidator()
	if res := oktaValidator.Setup(*deferred, args, nil); !res {
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
