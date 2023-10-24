package validator

import (
  "errors"
  "fmt"
  "os"
  "path/filepath"
  "strconv"
  "strings"
  "gopkg.in/ini.v1"

  "gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
  "gopkg.in/algolia/openvpn-auth-okta.v2/pkg/utils"
)

var (
  cfgDefaultPaths = [4]string{
    "/etc/okta-auth-validator/okta_openvpn.ini",
    "/etc/openvpn/okta_openvpn.ini",
    "/etc/okta_openvpn.ini",
    "okta_openvpn.ini",
  }
  pinsetDefaultPaths = [4]string{
    "/etc/okta-auth-validator/okta_pinset.cfg",
    "/etc/openvpn/okta_pinset.cfg",
    "/etc/okta_pinset.cfg",
    "okta_pinset.cfg",
  }
)

const passcodeLen int = 6

type PluginEnv struct {
  ControlFile string
  ClientIp    string
  CommonName  string
  Username    string
  Password    string
}

type PluginMode uint8
type OktaApiAuth = oktaApiAuth.OktaApiAuth

type OktaOpenVPNValidator struct {
  configFile      string
  pinsetFile      string
  usernameTrusted bool
  isUserValid     bool
  controlFile     string
  api             *OktaApiAuth
}

func NewOktaOpenVPNValidator() (*OktaOpenVPNValidator) {
  api := oktaApiAuth.NewOktaApiAuth()
  return &OktaOpenVPNValidator{
    usernameTrusted: false,
    isUserValid: false,
    controlFile: "",
    configFile: "",
    api: api,
  }
}

func (validator *OktaOpenVPNValidator) Setup(deferred bool, args []string, pluginEnv *PluginEnv) bool {
  if err := validator.ReadConfigFile(); err != nil {
    if deferred {
      /*
      * if invoked as a deferred plugin, we should always exit 0 and write result
      * in the control file.
      * here the validator control may not have been yet set, force it
      */
      validator.controlFile = os.Getenv("auth_control_file")
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
      if err := validator.LoadEnvVars(nil); err != nil {
        return false
      }
    }
  } else {
    // We're running in "Shared Object Plugin" mode
    // see https://openvpn.net/community-resources/using-alternative-authentication-methods/
    if err := validator.LoadEnvVars(pluginEnv); err != nil {
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
  validator.parsePassword()
  if err := validator.api.InitPool(); err != nil {
    return false
  }
  return true
}

func (validator *OktaOpenVPNValidator) parsePassword() {
  // If the password provided by the user is longer than a OTP (6 cars)
  // and the last 6 caracters are digits
  // then extract the user password (first) and the OTP
  userConfig := validator.api.UserConfig
  if len(userConfig.Password) > passcodeLen {
    last := userConfig.Password[len(userConfig.Password)-passcodeLen:]
    if _, err := strconv.Atoi(last); err == nil {
      userConfig.Passcode = last
      userConfig.Password = userConfig.Password[:len(userConfig.Password)-passcodeLen]
    } else {
      fmt.Printf("[%s] No TOTP found in password\n", userConfig.Username)
    }
  }
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
        // should never fail as err would be not nil only if cfgFile is not a string (or a []byte, a Reader)
        cfg, _ := ini.Load(cfgFile)
        apiConfig := validator.api.ApiConfig
        if err := cfg.Section("OktaAPI").MapTo(apiConfig); err != nil {
          fmt.Printf("Error parsing ini file: %s\n", err)
          return err
        }
        if apiConfig.Url == "" || apiConfig.Token == "" {
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
          pinsetArray := strings.Split(string(pinset), "\n")
          cleanPinset := utils.RemoveComments(utils.RemoveEmptyStrings(pinsetArray))
          validator.api.ApiConfig.AssertPin = cleanPinset
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

      apiConfig := validator.api.ApiConfig
      validator.usernameTrusted = true
      if apiConfig.UsernameSuffix != ""  && !strings.Contains(username, "@") {
        username = fmt.Sprintf("%s@%s", username, apiConfig.UsernameSuffix)
      }
      userConfig := validator.api.UserConfig
      userConfig.Username = username
      userConfig.Password = password
      userConfig.ClientIp ="0.0.0.0"
      return nil
    }
  }
}

func (validator *OktaOpenVPNValidator) LoadEnvVars(pluginEnv *PluginEnv) error {
  if pluginEnv == nil {
    pluginEnv = &PluginEnv{
      Username: os.Getenv("username"),
      CommonName: os.Getenv("common_name"),
      Password: os.Getenv("password"),
      ClientIp: utils.GetEnv("untrusted_ip", "0.0.0.0"),
      ControlFile: os.Getenv("auth_control_file"),
    }
  }
  validator.controlFile = pluginEnv.ControlFile

  if validator.controlFile == "" {
    fmt.Println("No control file found, if using a deferred plugin auth will stall and fail.")
  }
  // if the username comes from a certificate and AllowUntrustedUsers is false:
  // user is trusted
  // otherwise BE CAREFUL, username from OpenVPN credentials will be used !
  apiConfig := validator.api.ApiConfig
  if pluginEnv.CommonName != "" && !apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
    pluginEnv.Username = pluginEnv.CommonName
  }

  // if username is empty, there is an issue somewhere
  if pluginEnv.Username == "" {
    fmt.Println("No username or CN provided")
    return errors.New("No CN or username")
  }

  if pluginEnv.Password == "" {
    fmt.Println("No password provided")
    return errors.New("No password")
  }

  if !utils.CheckUsernameFormat(pluginEnv.Username) {
    fmt.Println("Username or CN invalid format")
    return errors.New("Invalid CN or username format")
  }

  if apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
  }
  if apiConfig.UsernameSuffix != ""  && !strings.Contains(pluginEnv.Username, "@") {
    pluginEnv.Username = fmt.Sprintf("%s@%s", pluginEnv.Username, apiConfig.UsernameSuffix)
  }

  userConfig := validator.api.UserConfig
  userConfig.Username = pluginEnv.Username
  userConfig.Password = pluginEnv.Password
  userConfig.ClientIp = pluginEnv.ClientIp
  return nil
}

func (validator *OktaOpenVPNValidator) Authenticate() error {
  if !validator.usernameTrusted {
    fmt.Printf("[%s] User is not trusted - failing\n", validator.api.UserConfig.Username)
    return errors.New("User not trusted")
  }
  if err := validator.api.Auth(); err == nil {
    validator.isUserValid = true
    return nil
  } else {
    return errors.New("Authentication failed")
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

  valToWrite := []byte("0")
  if validator.isUserValid {
    valToWrite = []byte("1")
  }
  if err := os.WriteFile(validator.controlFile, valToWrite, 0600); err !=nil {
    fmt.Printf("Failed to write to OpenVPN control file %s\n", validator.controlFile)
  }
}

