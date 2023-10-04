package types

type OktaAPI struct {
  Url                 string
  Token               string
  UsernameSuffix      string
  AllowUntrustedUsers bool
  // These can be modified in the 'okta_openvpn.ini' file.
  // By default, we retry for 2 minutes:
  MFAPushMaxRetries   int
  MFAPushDelaySeconds int
}

type OktaConfig struct {
  Username  string
  Password  string
  ClientIp  string
  AssertPin []string
}
