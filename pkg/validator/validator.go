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

var (
  cfgDefaultPaths = [3]string{
    "/etc/openvpn/okta_openvpn.ini",
    "/etc/okta_openvpn.ini",
    "okta_openvpn.ini",
  }
  pinsetDefaultPaths = [3]string{
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
  pinsetFile      string
  usernameTrusted bool
  isUserValid     bool
  controlFile     string
  apiConfig       *OktaAPI
  userConfig      *OktaUserConfig
}

func NewOktaOpenVPNValidator() (*OktaOpenVPNValidator) {
  return &OktaOpenVPNValidator{
    usernameTrusted: false,
    isUserValid: false,
    controlFile: "",
    configFile: "",
  }
}

func (validator *OktaOpenVPNValidator) IsUserValid() bool {
  return validator.isUserValid
}

func (validator *OktaOpenVPNValidator) SetControlFile(f string) {
  validator.controlFile = f
}

func (validator *OktaOpenVPNValidator) Setup(deferred bool, args []string) bool {
  if err := validator.ReadConfigFile(); err != nil {
    if deferred {
      /*
      * if invoked as a deferred plugin, we should always exit 0 and write result
      * in the control file.
      * here the validator control may not have been yet set, force it
      */
      validator.SetControlFile(os.Getenv("auth_control_file"))
      validator.WriteControlFile()
    }
    return false
  }

  if !deferred {
    // We're running in "Script Plugins" mode with "via-env" method
    // see "--auth-user-pass-verify cmd method" in
    //   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
    if len(args) > 0 {
      // via-file" method
      if err := validator.LoadViaFile(args[0]); err != nil {
        return false
      }
    } else {
      // "via-env" method
      if err := validator.LoadEnvVars(); err != nil {
        return false
      }
    }
  } else {
    // We're running in "Shared Object Plugin" mode
    // see https://openvpn.net/community-resources/using-alternative-authentication-methods/
    if err := validator.LoadEnvVars(); err != nil {
      validator.WriteControlFile()
      return false
    }
  }

  if err := validator.LoadPinset(); err != nil {
    if deferred {
      validator.WriteControlFile()
    }
    return false
  }
  return true
}

func (validator *OktaOpenVPNValidator) ReadConfigFile() (error) {
  var cfgPaths []string
  if validator.configFile == "" {
    for _, v := range cfgDefaultPaths {
      cfgPaths = append(cfgPaths, v)
    }
  } else {
    cfgPaths = append(cfgPaths, validator.configFile)
  }
  for _, cfgFile := range cfgPaths {
    if info, err := os.Stat(cfgFile); err != nil {
      continue
    } else {
      if info.IsDir() {
        continue
      } else {
        cfg, err := ini.Load(cfgFile)
        if err != nil {
          fmt.Printf("Error loading ini file: %s\n", err)
          return err
        }
        validator.apiConfig = &OktaAPI{
          AllowUntrustedUsers: false,
          MFARequired: false,
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
        validator.configFile = cfgFile
        return nil
      }
    }
  }
  fmt.Printf("No ini file found in %v\n", cfgPaths)
  return errors.New("No ini file found")
}

func (validator *OktaOpenVPNValidator) LoadPinset() (error) {
  var pinsetPaths []string
  if validator.pinsetFile == "" {
    for _, v := range pinsetDefaultPaths {
      pinsetPaths = append(pinsetPaths, v)
    }
  } else {
    pinsetPaths = append(pinsetPaths, validator.pinsetFile)
  }
  for _, pinsetFile := range pinsetPaths {
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
          validator.pinsetFile = pinsetFile
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
      viaFileInfos = utils.RemoveEmptyStrings(viaFileInfos)
      if len(viaFileInfos) < 2 {
        fmt.Printf("Invalid OpenVPN via-file %s content\n", path)
        return errors.New("Invalid via-file")
      }
      username := viaFileInfos[0]
      password := viaFileInfos[1]

      if !utils.CheckUsernameFormat(username) {
        fmt.Println("Username or CN invalid format")
        return errors.New("Invalid CN or username format")
      }

      validator.usernameTrusted = true
      if validator.apiConfig.UsernameSuffix != ""  && !strings.Contains(username, "@") {
        username = fmt.Sprintf("%s@%s", username, validator.apiConfig.UsernameSuffix)
      }
      validator.userConfig = &OktaUserConfig{
        Username: username,
        Password: password,
        ClientIp: "0.0.0.0",
      }
      return nil
    }
  }
}

func (validator *OktaOpenVPNValidator) LoadEnvVars() error {
  username := os.Getenv("username")
  commonName := os.Getenv("common_name")
  password := os.Getenv("password")
  clientIp := utils.GetEnv("untrusted_ip", "0.0.0.0")
  validator.controlFile = os.Getenv("auth_control_file")

  if validator.controlFile == "" {
    fmt.Println("No control file found, if using a deferred plugin auth will stall and fail.")
  }
  // if the username comes from a certificate and AllowUntrustedUsers is false:
  // user is trusted
  // otherwise BE CAREFUL, username from OpenVPN credentials will be used !
  if commonName != "" && !validator.apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
    username = commonName
  }

  // if username is empty, there is an issue somewhere
  if username == "" {
    fmt.Println("No username or CN provided")
    return errors.New("No CN or username")
  }

  if password == "" {
    fmt.Println("No password provided")
    return errors.New("No password")
  }

  if !utils.CheckUsernameFormat(username) {
    fmt.Println("Username or CN invalid format")
    return errors.New("Invalid CN or username format")
  }

  if validator.apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
  }
  if validator.apiConfig.UsernameSuffix != ""  && !strings.Contains(username, "@") {
    username = fmt.Sprintf("%s@%s", username, validator.apiConfig.UsernameSuffix)
  }

  validator.userConfig = &OktaUserConfig{
    Username: username,
    Password: password,
    ClientIp: clientIp,
  }
  return nil
}

func (validator *OktaOpenVPNValidator) Authenticate() {
  if !validator.usernameTrusted {
    fmt.Printf("[%s] User is not trusted - failing\n", validator.userConfig.Username)
    validator.isUserValid = false
    return
  }
  okta, err := oktaApiAuth.NewOktaApiAuth(validator.apiConfig, validator.userConfig)
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
func (validator *OktaOpenVPNValidator) checkControlFilePerm() error {
  if validator.controlFile == "" {
    return errors.New("Unknow control file")
  }

  if !utils.CheckNotWritable(validator.controlFile) {
    fmt.Printf("Refusing to authenticate. The file %s must not be writable by non-owners.",
      validator.controlFile)
    return errors.New("control file writable by non-owners")
  }
  dirName := filepath.Dir(validator.controlFile)
  if !utils.CheckNotWritable(dirName) {
    fmt.Printf("Refusing to authenticate. The directory containing the file %s must not be writable by non-owners.",
      validator.controlFile)
    return errors.New("control file dir writable by non-owners")
  }

  return nil
}

func (validator *OktaOpenVPNValidator) WriteControlFile() {
  if err := validator.checkControlFilePerm(); err != nil {
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

