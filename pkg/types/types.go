package types

// Contains the configuration for the Okta API connection
// Those configuration options are read from okta_openvpn.ini
type OktaAPI struct {
  Url                 string
  Token               string
  UsernameSuffix      string
  AssertPin           []string
  MFARequired         bool // default: false
  AllowUntrustedUsers bool // default: false
  MFAPushMaxRetries   int // default = 20
  MFAPushDelaySeconds int // default = 3
}

// User credentials and informations
type OktaUserConfig struct {
  Username  string
  Password  string
  Passcode  string
  ClientIp  string
}

type PluginEnv struct {
  ControlFile string
  ClientIp    string
  CommonName  string
  Username    string
  Password    string
}
