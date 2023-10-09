package types

// Contains the configuration for the Okta API connection
// Those configuration options are read from okta_openvpn.ini
type OktaAPI struct {
  Url                 string
  Token               string
  UsernameSuffix      string
  AssertPin           []string
  AllowUntrustedUsers bool // default: false
  MFAPushMaxRetries   int // default = 20
  MFAPushDelaySeconds int // default = 3
}

// User credentials and informations
type OktaUserConfig struct {
  Username  string
  Password  string
  ClientIp  string
}

