package validator

import (
  //"crypto/x509"
  //"encoding/base64"
  //"encoding/json"

  // hazmat backend
  //"encoding/hex"
  //"encoding/pem"
  "fmt"
  "os"
  "strings"
  //"crypto/sha256" 

  "gopkg.in/algolia/okta-openvpn/pkg/types.golang"

  "gopkg.in/ini.v1"

)

type OktaAPI = types.OktaAPI
type OktaConfig = types.OktaConfig

type OktaOpenVPNValidator struct {
  username_trusted      bool
  user_valid            bool
  control_file          string
  site_config           *OktaAPI
  config_file           string
  okta_config           *OktaConfig
}

func getEnv(key, fallback string) string {
  if value, ok := os.LookupEnv(key); ok {
    return value
  } else if len(value) == 0 {
    return fallback
  }
  return fallback
}

func NewOktaOpenVPNValidator() (*OktaOpenVPNValidator) {
	return &OktaOpenVPNValidator{
    username_trusted: false,
    user_valid: false,
    control_file: "",
    config_file: "",
  }
}

func (oovv *OktaOpenVPNValidator) ReadConfigFile() (bool, error) {
  var cfg_path [3]string
  if oovv.config_file == "" {
    cfg_path = cfg_path_defaults
  }/* else {
    // TODO
    cfg_path = append(cfg_path, oovv.config_file)
  }*/
  for _, cfg_file := range cfg_path {
    if _, err := os.Stat(cfg_file); err != nil {
      // TODO: check perm
      continue
    }
    fmt.Println("processing ini file: ", cfg_file)
    cfg, _ := ini.Load(cfg_file)
    oovv.site_config = &OktaAPI{
      AllowUntrustedUsers: false,
      MFAPushMaxRetries: 20,
      MFAPushDelaySeconds: 3,
    }
    if err := cfg.Section("OktaAPI").MapTo(oovv.site_config); err != nil {
      fmt.Println("Error parsing ini file: ", err)
      return false, err
    }
    if oovv.site_config.Url == "" || oovv.site_config.Token == "" {
      fmt.Println("Missing param Url or Token")
      return false, nil
    }
  }
  fmt.Printf("%+v\n", oovv.site_config)
  return true, nil
}

func (oovv *OktaOpenVPNValidator) LoadEnvVars() (bool, error) {
  username := os.Getenv("username")
  password := os.Getenv("password")
  clientIp := getEnv("untrusted_ip", "0.0.0.0")
  assertPin := os.Getenv("assert_pin")
  oovv.control_file = os.Getenv("auth_control_file")

  if oovv.control_file == "" {
    fmt.Println("No control file found, if using a deferred plugin auth will stall and fail.")
  }
  if username != "" {
    oovv.username_trusted = true
  }
  if oovv.site_config.AllowUntrustedUsers {
    oovv.username_trusted = true
  }
  if oovv.site_config.UsernameSuffix != ""  && strings.Contains(username, "@") {
    username = fmt.Sprintf("%s@%s", username, oovv.site_config.UsernameSuffix)
  }

  oovv.okta_config = &OktaConfig{
    Username: username,
    Password: password,
    ClientIp: clientIp,
  }
  if assertPin != "" {
    oovv.okta_config.AssertPin = []string{assertPin}
  } else {
    oovv.okta_config.AssertPin = []string{
      // algolia.okta.com
      "MaqlcUgk2mvY/RFSGeSwBRkI+rZ6/dxe/DuQfBT/vnQ=",
      // okta.com
      "r5EfzZxQVvQpKo3AgYRaT7X2bDO/kj3ACwmxfdT2zt8=",
      "MaqlcUgk2mvY/RFSGeSwBRkI+rZ6/dxe/DuQfBT/vnQ=",
      "72G5IEvDEWn+EThf3qjR7/bQSWaS2ZSLqolhnO6iyJI=",
      "rrV6CLCCvqnk89gWibYT0JO6fNQ8cCit7GGoiVTjCOg=",
      // oktapreview.com
      "jZomPEBSDXoipA9un78hKRIeN/+U4ZteRaiX8YpWfqc=",
      "axSbM6RQ+19oXxudaOTdwXJbSr6f7AahxbDHFy3p8s8=",
      "SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE=",
      "ylP0lMLMvBaiHn0ihLxHjzvlPVQNoyQ+rMiaj0da/Pw=",
      // internal testing
      "W2qOJ9F9eo3CYHzL5ZIjYEizINI1cUPEb7yD45ihTXg=",
      "PJ1QGTlW5ViFNhswMsYKp4X8C7KdG8nDW4ZcXLmYMyI=",
      "5LlRWGTBVjpfNXXU5T7cYVUbOSPcgpMgdjaWd/R9Leg=",
      "lpaMLlEsp7/dVZoeWt3f9ciJIMGimixAIaKNsn9/bCY=",
      // internal testing
      "Uit61pzomPOIy0svL1z4OUx3FMBr9UWQVdyG7ZlSLK8=",
      "Ul2vkypIA80/JDebYsXq8FGdtmtrx5WJAAHDlSwWOes=",
      "rx1UuNLIkJs53Jd60G/zY947XcDIf56JyM/yFJyR/GE=",
      "VvpiE4cl60BvOU8X4AfkWeUPsmRUSh/nVbJ2rnGDZHI=",
    }
  }
  fmt.Printf("%+v\n", oovv)
  fmt.Printf("%+v\n", oovv.okta_config)
  return true, nil
}

func (oovv *OktaOpenVPNValidator) Authenticate() (bool) {
  var err error
  if !oovv.username_trusted {
    fmt.Println("[", oovv.okta_config.Username,"] User is not trusted - failing")
    return false
  }
  okta := NewOktaApiAuth(oovv.site_config, oovv.okta_config)
  oovv.user_valid, err = okta.Auth()
  if err != nil {
    fmt.Println("[", oovv.okta_config.Username, "]",
      " User at [", oovv.okta_config.ClientIp, "]")
  }
  return oovv.user_valid
}
