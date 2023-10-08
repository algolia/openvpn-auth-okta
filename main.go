package main

import (
  "bytes"
  "crypto/sha256"
  "crypto/tls"
  "crypto/x509"
  "io"
  "encoding/base64"
  "encoding/json"
  "errors"
  "flag"
  "fmt"
  "net/http"
  "net/url"
  "os"
  "path/filepath"
  "regexp"
  "slices"
  "strings"
  "strconv"
  "time"
  "gopkg.in/ini.v1"
)

/*
type OktaAPI = types.OktaAPI
type OktaUserConfig = types.OktaUserConfig
*/

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
  debug *bool
)

const userAgent string = "OktaOpenVPN/2.1.0 (Linux 5.4.0) Go-http-client/1.21.1"

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

type oktaApiAuth struct {
  APICfg    *OktaAPI
  UserCfg   *OktaUserConfig
  Passcode  string
  Pool      *http.Client
  UserAgent string
}

type OktaOpenVPNValidator struct {
  configFile      string
  usernameTrusted bool
  isUserValid     bool
  controlFile     string
  apiConfig       *OktaAPI
  oktaUserConfig  *OktaUserConfig
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
    usernameTrusted: false,
    isUserValid: false,
    controlFile: "",
    configFile: "",
  }
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
      return nil
    }
  }
}

func (validator *OktaOpenVPNValidator) LoadEnvVars() {
  username := os.Getenv("username")
  commonName := os.Getenv("common_name")
  password := os.Getenv("password")
  clientIp := getEnv("untrusted_ip", "0.0.0.0")
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
}

func (validator *OktaOpenVPNValidator) Authenticate() {
  if !validator.usernameTrusted {
    fmt.Printf("[%s] User is not trusted - failing\n", validator.oktaUserConfig.Username)
    validator.isUserValid = false
    return
  }
  okta, err := newOktaApiAuth(validator.apiConfig, validator.oktaUserConfig)
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

// Check that path is not group or other writable
func checkNotWritable(path string) bool {
  sIWGRP := 0b000010000 // Group write permissions
  sIWOTH := 0b000000010 // Other write permissions

  fileInfo, err := os.Stat(path)
  if err != nil {
    return false
  }

  fileMode := fileInfo.Mode().Perm()
  if int(fileMode)&sIWGRP == sIWGRP || int(fileMode)&sIWOTH == sIWOTH {
    return false
  }
  return true
}

// validate the OpenVPN control file and its directory permissions
func (validator *OktaOpenVPNValidator) CheckControlFilePerm() error {
  if validator.controlFile == "" {
    return errors.New("Unknow control file")
  }

  if !checkNotWritable(validator.controlFile) {
    msg := fmt.Sprintf("Refusing to authenticate. The file %s must not be writable by non-owners.",
      validator.controlFile)
    return errors.New(msg)
  }
  dirName := filepath.Dir(validator.controlFile)
  if !checkNotWritable(dirName) {
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

// Prepare an http client with the proper TLS config
// validate the server public key against our list of pinned key fingerprint
func connectionPool(oktaURL string, pinset []string) (*http.Client, error) {
  if rawURL, err := url.Parse(oktaURL); err != nil {
    return nil, err
  } else {
    port := rawURL.Port()
    if port == "" {
      port="443"
    }
    // Connect to the server, fetch its public key and validate it againts the
    // base64 digest in pinset slice
    tcpURL := fmt.Sprintf("%s:%s", rawURL.Hostname(), port)
    conn, err := tls.Dial("tcp", tcpURL, &tls.Config{InsecureSkipVerify: true})
    if err != nil {
      fmt.Printf("Error in Dial: %s\n", err)
      return nil, err
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
    for _, cert := range certs {
      if !cert.IsCA {
        // Compute public key base64 digest
        derPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
        if err != nil {
	        return nil, err
	      }
        pubKeySha := sha256.Sum256(derPubKey)
        digest := base64.StdEncoding.EncodeToString([]byte(string(pubKeySha[:])))

        if !slices.Contains(pinset, digest) {
          fmt.Printf("Refusing to authenticate because host %s failed %s\n%s\n",
            rawURL.Hostname(),
            "a TLS public key pinning check.",
            "Please contact support@okta.com with this error message")
          return nil, errors.New("Invalid key pinning")
        }
      }
    }
  }

  tlsCfg := &tls.Config{
    InsecureSkipVerify: false,
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      // TLS 1.3 cipher suites
      tls.TLS_AES_128_GCM_SHA256,
      tls.TLS_AES_256_GCM_SHA384,
      tls.TLS_CHACHA20_POLY1305_SHA256,
    },
  }
  t := &http.Transport{
    MaxIdleConns: 5,
    MaxConnsPerHost: 5,
    MaxIdleConnsPerHost: 5,
    TLSClientConfig: tlsCfg,
  }
  httpClient := &http.Client{
    Timeout:   10 * time.Second,
    Transport: t,
  }
  return httpClient, nil
}

func newOktaApiAuth(apiConfig *OktaAPI, userConfig *OktaUserConfig) (auth *oktaApiAuth, err error) {
  passcodeLen := 6
  /*
  utsname := unix.Utsname{}
  _ = unix.Uname(&utsname)
  userAgent := fmt.Sprintf("OktaOpenVPN/2.1.0 (%s %s) Go-http-client/%s",
    utsname.Sysname,
    utsname.Release,
    runtime.Version()[2:])
  fmt.Printf("agent: %s\n", userAgent)

  using dynamic user agent does not work ....
  so for now use a const var
  */

  auth = &oktaApiAuth{APICfg: apiConfig, UserCfg: userConfig, UserAgent: userAgent}
  // If the password provided by the user is longer than a OTP (6 cars)
  // and the last 6 caracters are digits
  // then extract the user password (first) and the OTP
  if len(userConfig.Password) > passcodeLen {
    last := userConfig.Password[len(userConfig.Password)-passcodeLen:]
    if _, err := strconv.Atoi(last); err == nil {
      auth.Passcode = last
      userConfig.Password = userConfig.Password[:len(userConfig.Password)-passcodeLen]
    } else {
      fmt.Printf("[%s] No TOTP found in password\n", auth.UserCfg.Username)
    }
  }
  
  auth.Pool, err = connectionPool(apiConfig.Url, apiConfig.AssertPin)
  if err != nil {
    return nil, err
  }
  return auth, nil
}

// Do a POST http request to the Okta API using the path and payload provided
func (auth *oktaApiAuth) OktaReq(path string, data map[string]string) (a map[string]interface{}, err error) {
  u, err := url.ParseRequestURI(auth.APICfg.Url)
  if err != nil {
    fmt.Printf("Error validating url: %s\n", err)
    return nil, err
  }

  u.Path = fmt.Sprintf("/api/v1%s", path)

  ssws := fmt.Sprintf("SSWS %s", auth.APICfg.Token)
  headers := map[string]string{
    "User-Agent": auth.UserAgent,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": ssws,
  }
  if auth.UserCfg.ClientIp != "0.0.0.0" {
    headers["X-Forwarded-For"] = auth.UserCfg.ClientIp
  }

  jsonData, err := json.Marshal(data)
  if err != nil {
    fmt.Printf("Error marshaling request payload: %s\n", err)
    return nil, err
  }
  r, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonData))
  if err != nil {
    fmt.Printf("Error creating http request: %s\n", err)
    return nil, err
  }
  for k, v := range headers {
    r.Header.Add(k, v)
  }
  resp, err := auth.Pool.Do(r)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()
  jsonBody, err := io.ReadAll(resp.Body)
  if err != nil {
    fmt.Printf("Error reading Okta API response: %s\n", err)
    return nil, err
  }
  err = json.Unmarshal(jsonBody, &a)
  if err != nil {
    fmt.Printf("Error unmarshaling Okta API response: %s\n", err)
    return nil, err
  }
  return a, nil
}

// Call the preauth Okta API endpoint
func (auth *oktaApiAuth) PreAuth() (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
  data := map[string]string{
    "username": auth.UserCfg.Username,
    "password": auth.UserCfg.Password,
  }
  return auth.OktaReq("/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *oktaApiAuth) DoAuth(fid string, stateToken string) (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
  path := fmt.Sprintf("/authn/factors/%s/verify", fid)
  data := map[string]string{
    "fid": fid,
    "stateToken": stateToken,
    "passCode": auth.Passcode,
  }
  return auth.OktaReq(path, data)
}

func (auth *oktaApiAuth) CancelAuth(stateToken string) (map[string]interface{}, error) {
  data := map[string]string{
    "stateToken": stateToken,
  }
  return auth.OktaReq("/authn/cancel", data)
}

func (auth *oktaApiAuth) Auth() (error) {
  var status string
  if auth.UserCfg.Username == "" && auth.UserCfg.Password == "" {
    fmt.Printf("Missing username or password for user: %s (%s) - %s\n",
      auth.UserCfg.Username,
      auth.UserCfg.ClientIp,
      "Reported username may be 'None' due to this")
    return errors.New("Missing username or password")
  }
  fmt.Printf("[%s] Authenticating\n", auth.UserCfg.Username)
  retp, err := auth.PreAuth()
  if err != nil {
    fmt.Printf("[%s] Error connecting to the Okta API: %s\n", auth.UserCfg.Username, err)
    return err
  }

  if _, ok := retp["errorCauses"]; ok {
    fmt.Printf("[%s] pre-authentication failed: %s\n", auth.UserCfg.Username, retp["errorSummary"])
    return errors.New("pre-authentication failed")
  }
  if st, ok := retp["status"]; ok {
    status = st.(string)
    switch status {
    case "SUCCESS":
      fmt.Printf("[%s] allowed without MFA - refused\n", auth.UserCfg.Username)
      return errors.New("No MFA")
    case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
      fmt.Printf("[%s] user needs to enroll first\n", auth.UserCfg.Username)
      return errors.New("Needs to enroll")
    case "MFA_REQUIRED", "MFA_CHALLENGE":
      fmt.Printf("[%s] user password validates, checking second factor\n", auth.UserCfg.Username)
      factors := retp["_embedded"].(map[string]interface{})["factors"].([]interface{})
      supportedFactorTypes := []string{"token:software:totp", "push"}
      var res map[string]interface{}
      for _, factor := range factors {
        factorType := factor.(map[string]interface{})["factorType"].(string)
        if !slices.Contains(supportedFactorTypes, factorType) {
          fmt.Printf("Unsupported factortype: %s, skipping\n", factorType)
          continue
        }
        fid := factor.(map[string]interface{})["id"].(string)
        stateToken := retp["stateToken"].(string)
        res, err = auth.DoAuth(fid, stateToken)
        if err != nil {
          _, _ = auth.CancelAuth(stateToken)
          return err
        }
        checkCount := 0
        for res["factorResult"] == "WAITING" {
          time.Sleep(time.Duration(auth.APICfg.MFAPushDelaySeconds)  * time.Second)
          res, err = auth.DoAuth(fid, stateToken)
          if err != nil {
            _, _ = auth.CancelAuth(stateToken)
            return err
          }
          if checkCount++; checkCount > auth.APICfg.MFAPushMaxRetries {
            fmt.Printf("[%s] User MFA push timed out\n", auth.UserCfg.Username)
            _, _ = auth.CancelAuth(stateToken)
            return errors.New("MFA timeout")
          }
        }
        if _, ok := res["status"]; ok {
          if res["status"] == "SUCCESS" {
            fmt.Printf("[%s] User is now authenticated with MFA via Okta API\n", auth.UserCfg.Username)
            return nil
          } else {
            fmt.Printf("[%s] User MFA push failed: %s\n", auth.UserCfg.Username, res["factorResult"])
            _, _ = auth.CancelAuth(stateToken)
            return errors.New("MFA failed")
          }
        }
      }
      if _, ok := res["errorCauses"]; ok {
        cause := res["errorCauses"].([]interface{})[0]
        errorSummary := cause.(map[string]interface{})["errorSummary"].(string)
        fmt.Printf("[%s] User MFA token authentication failed: %s\n", auth.UserCfg.Username, errorSummary)
        return errors.New(errorSummary)
      }
      return errors.New("Unknown error")

    default:
      fmt.Printf("Unknown preauth status: %s\n", status)
      return errors.New("Unknown preauth status")
    }
  }

  fmt.Printf("[%s] User is not allowed to authenticate: %s\n", auth.UserCfg.Username, status)
  return errors.New("Not allowed")
}

func main() {
  debug = flag.Bool("d", false, "enable debugging")
	flag.Parse()
	args := flag.Args()
  if *debug {
    fmt.Println("DEBUG MODE")
  }

  validator := NewOktaOpenVPNValidator()
  if err := validator.ReadConfigFile(); err != nil {
    os.Exit(1)
  }

  if len(args) > 0 {
    // We're running in "Script Plugins" mode with "via-file" method
    // see "--auth-user-pass-verify cmd method" in
    //   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
    if err := validator.LoadViaFile(args[0]); err != nil {
      os.Exit(1)
    }
  } else {
    // We're running in "Script Plugins" mode with "via-env" method
    // or in "Shared Object Plugin" mode
    // see https://openvpn.net/community-resources/using-alternative-authentication-methods/
    validator.LoadEnvVars()
  }
  /* OpenVPN doc says:
  To protect against a client passing a maliciously formed username or password string,
  the username string must consist only of these characters:
  alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
  */
  match, err := regexp.MatchString(`^([[:alpha:]]|[_\-\.@])*$`, validator.oktaUserConfig.Username);
  if err != nil || !match {
    fmt.Println("Invalid username format")
    os.Exit(1)
  }

  if err := validator.LoadPinset(); err != nil {
    os.Exit(1)
  }
  validator.Authenticate()
  validator.WriteControlFile()
  if validator.isUserValid {
    os.Exit(0)
  }
  os.Exit(1)
}
