package main

import (
  //"crypto/x509"
  //"encoding/base64"
  //"encoding/json"

  // hazmat backend
  //"encoding/hex"
  //"encoding/pem"
  "errors"
  "os"
  //"crypto/sha256"

  "gopkg.in/algolia/okta-openvpn.v2/pkg/types"
  "gopkg.in/algolia/okta-openvpn.v2/pkg/validator"
)

type OktaAPI = types.OktaAPI
type OktaConfig = types.OktaConfig

var (
  cfg_path_defaults = [3]string{
	  "/etc/openvpn/okta_openvpn.ini",
		"/etc/okta_openvpn.ini",
		"okta_openvpn.ini",
	}
)


type OktaApiAuth struct {
  APICfg  *OktaAPI
  UserCfg *OktaConfig
}

func NewOktaApiAuth(siteConfig *OktaAPI, oktaConfig *OktaConfig) (*OktaApiAuth) {
  return &OktaApiAuth{APICfg: siteConfig, UserCfg: oktaConfig}
  /*
  self.okta_urlparse = urllib.parse.urlparse(okta_url)
  url_new = (self.okta_urlparse.scheme,
             self.okta_urlparse.netloc,
             '', '', '', '')
  self.okta_url = urllib.parse.urlunparse(url_new)
  */
}

func (*OktaApiAuth) Auth() (bool, error) {
  return false, errors.New("NOOP")
}


func main() {
  vali := validator.NewOktaOpenVPNValidator()
  _, _ = vali.ReadConfigFile()
  _, _ = vali.LoadEnvVars()
  //validator.run()
  if vali.user_valid {
    os.Exit(0)
  }
  os.Exit(1)
}
