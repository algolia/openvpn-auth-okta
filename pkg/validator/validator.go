package validator

import (
  "errors"
  "fmt"
  "os"
  "path/filepath"
  "strings"
  "gopkg.in/ini.v1"

  "gopkg.in/algolia/okta-openvpn.v2/pkg/oktaApiAuth"
  "gopkg.in/algolia/okta-openvpn.v2/pkg/types"
  "gopkg.in/algolia/okta-openvpn.v2/pkg/utils"
)

const (
  ViaFile PluginMode = iota
  ViaEnv             = iota
)

var (
  cfg_path_defaults = [3]string{
	  "/etc/openvpn/okta_openvpn.ini",
		"/etc/okta_openvpn.ini",
		"okta_openvpn.ini",
	}
  pinset_paths = [3]string{
	  "/etc/openvpn/okta_pinset.cfg",
		"/etc/okta_pinset.cfg",
		"okta_pinset.cfg",
  }
)

type OktaAPI = types.OktaAPI
type OktaUserConfig = types.OktaUserConfig

type PluginMode uint8

type OktaOpenVPNValidator struct {
  configFile      string
  usernameTrusted bool
  isUserValid     bool
  controlFile     string
  apiConfig       *OktaAPI
  oktaUserConfig  *OktaUserConfig
  mode            PluginMode
}

func NewOktaOpenVPNValidator() (*OktaOpenVPNValidator) {
	return &OktaOpenVPNValidator{
    usernameTrusted: false,
    isUserValid: false,
    controlFile: "",
    configFile: "",
  }
}

func (validator *OktaOpenVPNValidator) Username() string {
  return validator.oktaUserConfig.Username
}

func (validator *OktaOpenVPNValidator) IsUserValid() bool {
  return validator.isUserValid
}

func (validator *OktaOpenVPNValidator) Mode() PluginMode {
  return validator.mode
}

func (validator *OktaOpenVPNValidator) ReadConfigFile() (error) {
  var cfg_path []string
  if validator.configFile == "" {
    for _, v := range cfg_path_defaults {
      cfg_path = append(cfg_path, v)
    }
  } else {
    cfg_path = append(cfg_path, validator.configFile)
  }
  for _, cfg_file := range cfg_path {
    if info, err := os.Stat(cfg_file); err != nil {
      continue
    } else {
      if info.IsDir() {
        continue
      } else {
        cfg, err := ini.Load(cfg_file)
        if err != nil {
          fmt.Printf("Error loading ini file: %s\n", err)
          return err
        }
        validator.apiConfig = &OktaAPI{
          AllowUntrustedUsers: false,
          MFAPushMaxRetries: 20,
          MFAPushDelaySeconds: 3,
        }
        if err := cfg.Section("OktaAPI").MapTo(validator.apiConfig); err != nil {
          fmt.Printf("Error parsing ini file: %s\n", err)
          return err
        }
        if validator.apiConfig.Url == "" || validator.apiConfig.Token == "" {
          fmt.Println("Missing param Url or Token")
          return errors.New("Missing param Url or Token")
        }
        return nil
      }
    }
  }
  fmt.Printf("No ini file found in %v\n", cfg_path)
  return errors.New("No ini file found")
}

func (validator *OktaOpenVPNValidator) LoadPinset() (error) {
  for _, pinsetFile := range pinset_paths {
    if info, err := os.Stat(pinsetFile); err != nil {
      continue
    } else {
      if info.IsDir() {
        continue
      } else {
        if pinset, err := os.ReadFile(pinsetFile); err != nil {
          fmt.Printf("Can not read pinset config file %s\n", pinsetFile)
          return err
        } else {
          validator.apiConfig.AssertPin = strings.Split(string(pinset), "\n")
          return nil
        }
      }
    }
  }
  return errors.New("No pinset file found")
}

func (validator *OktaOpenVPNValidator) LoadViaFile(path string) (error){
  if _, err := os.Stat(path); err != nil {
      fmt.Printf("OpenVPN via-file %s does not exists\n", path)
    return err
  } else {
    if viaFileBuf, err := os.ReadFile(path); err != nil {
      fmt.Printf("Can not read OpenVPN via-file %s\n", path)
      return err
    } else {
      viaFileInfos := strings.Split(string(viaFileBuf), "\n")
      if len(viaFileInfos) != 2 {
        fmt.Printf("Invalid OpenVPN via-file %s content\n", path)
        return errors.New("Invalid via-file")
      }
      username := viaFileInfos[0]
      password := viaFileInfos[1]
      if username != "" {
        validator.usernameTrusted = true
      }
      if validator.apiConfig.AllowUntrustedUsers {
        validator.usernameTrusted = true
      }
      if validator.apiConfig.UsernameSuffix != ""  && !strings.Contains(username, "@") {
        username = fmt.Sprintf("%s@%s", username, validator.apiConfig.UsernameSuffix)
      }
      validator.oktaUserConfig = &OktaUserConfig{
        Username: username,
        Password: password,
        ClientIp: "0.0.0.0",
      }
      validator.mode = ViaFile
      return nil
    }
  }
}

func (validator *OktaOpenVPNValidator) LoadEnvVars() {
  username := os.Getenv("username")
  commonName := os.Getenv("common_name")
  password := os.Getenv("password")
  clientIp := utils.GetEnv("untrusted_ip", "0.0.0.0")
  validator.controlFile = os.Getenv("auth_control_file")

  if validator.controlFile == "" {
    fmt.Println("No control file found, if using a deferred plugin auth will stall and fail.")
  }
  if commonName != "" {
    validator.usernameTrusted = true
  }
  if validator.apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
  }
  if validator.apiConfig.UsernameSuffix != ""  && !strings.Contains(username, "@") {
    username = fmt.Sprintf("%s@%s", username, validator.apiConfig.UsernameSuffix)
  }

  validator.oktaUserConfig = &OktaUserConfig{
    Username: username,
    Password: password,
    ClientIp: clientIp,
  }
  validator.mode = ViaEnv
}

func (validator *OktaOpenVPNValidator) Authenticate() {
  if !validator.usernameTrusted {
    fmt.Printf("[%s] User is not trusted - failing\n", validator.oktaUserConfig.Username)
    validator.isUserValid = false
    return
  }
  okta, err := oktaApiAuth.NewOktaApiAuth(validator.apiConfig, validator.oktaUserConfig)
  if err != nil {
    validator.isUserValid = false
    return
  }

  if err := okta.Auth(); err != nil {
    validator.isUserValid = false
  } else {
    validator.isUserValid = true
  }
}

// validate the OpenVPN control file and its directory permissions
func (validator *OktaOpenVPNValidator) CheckControlFilePerm() error {
  if validator.controlFile == "" {
    return errors.New("Unknow control file")
  }

  if !utils.CheckNotWritable(validator.controlFile) {
    msg := fmt.Sprintf("Refusing to authenticate. The file %s must not be writable by non-owners.",
      validator.controlFile)
    return errors.New(msg)
  }
  dirName := filepath.Dir(validator.controlFile)
  if !utils.CheckNotWritable(dirName) {
    msg := fmt.Sprintf("Refusing to authenticate. The directory containing the file %s must not be writable by non-owners.",
      validator.controlFile)
    return errors.New(msg)
  }

  return nil
}

func (validator *OktaOpenVPNValidator) WriteControlFile() {
  if err := validator.CheckControlFilePerm(); err != nil {
    return
  }
  if validator.isUserValid {
    if err := os.WriteFile(validator.controlFile, []byte("1"), 0600); err !=nil {
      fmt.Printf("Failed to write to OpenVPN control file %s\n", validator.controlFile)
    }
  } else {
    if err := os.WriteFile(validator.controlFile, []byte("0"), 0600); err !=nil {
      fmt.Printf("Failed to write to OpenVPN control file %s\n", validator.controlFile)
    }
  }
}

