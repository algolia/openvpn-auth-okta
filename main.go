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
  "fmt"
  //"golang.org/x/sys/unix"
  "net/http"
  "net/url"
  "os"
  "path/filepath"
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
)

const (
  passcodeLen int = 6
)

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

type OktaUserConfig struct {
  Username  string
  Password  string
  ClientIp  string
  AssertPin []string
}

type OktaApiAuth struct {
  APICfg    *OktaAPI
  UserCfg   *OktaUserConfig
  Passcode  string
  Pool      *http.Client
  UserAgent string
}

type OktaOpenVPNValidator struct {
  usernameTrusted bool
  isUserValid     bool
  controlFile     string
  apiConfig       *OktaAPI
  configFile      string
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
  var cfg_path [3]string
  if validator.configFile == "" {
    cfg_path = cfg_path_defaults
  }/* else {
    // TODO
    cfg_path = append(cfg_path, validator.configFile)
  }*/
  for _, cfg_file := range cfg_path {
    if info, err := os.Stat(cfg_file); err != nil {
      continue
    } else {
      if info.IsDir() {
        continue
      } else {
        cfg, err := ini.Load(cfg_file)
        if err != nil {
          fmt.Println("Error loading ini file: ", err)
          return err
        }
        validator.apiConfig = &OktaAPI{
          AllowUntrustedUsers: false,
          MFAPushMaxRetries: 20,
          MFAPushDelaySeconds: 3,
        }
        if err := cfg.Section("OktaAPI").MapTo(validator.apiConfig); err != nil {
          fmt.Println("Error parsing ini file: ", err)
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

func (validator *OktaOpenVPNValidator) LoadEnvVars() (error) {
  username := os.Getenv("username")
  password := os.Getenv("password")
  clientIp := getEnv("untrusted_ip", "0.0.0.0")
  assertPin := os.Getenv("assert_pin")
  validator.controlFile = os.Getenv("auth_control_file")

  if validator.controlFile == "" {
    fmt.Println("No control file found, if using a deferred plugin auth will stall and fail.")
  }
  if username != "" {
    validator.usernameTrusted = true
  }
  if validator.apiConfig.AllowUntrustedUsers {
    validator.usernameTrusted = true
  }
  if validator.apiConfig.UsernameSuffix != ""  && strings.Contains(username, "@") {
    username = fmt.Sprintf("%s@%s", username, validator.apiConfig.UsernameSuffix)
  }

  validator.oktaUserConfig = &OktaUserConfig{
    Username: username,
    Password: password,
    ClientIp: clientIp,
  }
  if assertPin != "" {
    validator.oktaUserConfig.AssertPin = []string{assertPin}
  } else {
    pinsetFile := "okta_pinset.cfg"
    if pinset, err := os.ReadFile(pinsetFile); err != nil {
      fmt.Printf("Can not read pinset config file %s\n", pinsetFile)
      return err
    } else {
      validator.oktaUserConfig.AssertPin = strings.Split(string(pinset), "\n")
    }
  }
  return nil
}

func (validator *OktaOpenVPNValidator) Authenticate() (bool) {
  var err error
  if !validator.usernameTrusted {
    fmt.Println("[", validator.oktaUserConfig.Username,"] User is not trusted - failing")
    return false
  }
  okta, err := NewOktaApiAuth(validator.apiConfig, validator.oktaUserConfig)
  if err != nil {
    return false
  }
  validator.isUserValid, err = okta.Auth()
  if err != nil {
    fmt.Println("[", validator.oktaUserConfig.Username, "]",
      "User at [", validator.oktaUserConfig.ClientIp, "]",
      "authentication failed, because OktaApiAuth.Auth failed - ",
      err)
  }
  return validator.isUserValid
}

func checkNotWritable(path string) bool {
  sIWGRP := 0b000010000
  sIWOTH := 0b000000010

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

func (validator *OktaOpenVPNValidator) WriteControlFile() (err error) {
  if err = validator.CheckControlFilePerm(); err != nil {
    return err
  }
  if validator.isUserValid {
    if err := os.WriteFile(validator.controlFile, []byte("1"), 0600); err !=nil {
      return err
    }
  } else {
    if err := os.WriteFile(validator.controlFile, []byte("0"), 0600); err !=nil {
      return err
    }
  }
  return nil
}

func ConnectionPool(oktaURL string, pinset []string) (*http.Client, error) {
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
      fmt.Println("Error in Dial", err)
      return nil, err
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
    for _, cert := range certs {
      if !cert.IsCA {
        // Compute public key base64 digest
        derPubKey, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
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

func NewOktaApiAuth(siteConfig *OktaAPI, oktaConfig *OktaUserConfig) (auth *OktaApiAuth, err error) {
  /*
  utsname := unix.Utsname{}
  _ = unix.Uname(&utsname)
  userAgent := fmt.Sprintf("OktaOpenVPN/2.1.0 (%s %s) Go-http-client/%s",
    utsname.Sysname,
    utsname.Release,
    runtime.Version()[2:])
  fmt.Printf("agent: %s\n", userAgent)

  using dynamic user agent does not work ....
  */

  userAgent := "OktaOpenVPN/2.1.0 (Linux 5.4.0) Go-http-client/1.21.1"
  auth = &OktaApiAuth{APICfg: siteConfig, UserCfg: oktaConfig, UserAgent: string(userAgent)}
  if len(oktaConfig.Password) > passcodeLen {
    last := oktaConfig.Password[len(oktaConfig.Password)-passcodeLen:]
    if _, err := strconv.Atoi(last); err == nil {
      auth.Passcode = last
      oktaConfig.Password = oktaConfig.Password[:len(oktaConfig.Password)-passcodeLen]
    }
  }
  
  auth.Pool, err = ConnectionPool(siteConfig.Url, oktaConfig.AssertPin)
  if err != nil {
    return nil, err
  }
  return auth, nil
}

func (auth *OktaApiAuth) OktaReq(path string, data map[string]string) (a map[string]interface{}, err error) {
  u, _ := url.ParseRequestURI(auth.APICfg.Url)
  u.Path = fmt.Sprintf("/api/v1%s", path)

  ssws := fmt.Sprintf("SSWS %s", auth.APICfg.Token)
  headers := map[string]string{
    "User-Agent": auth.UserAgent,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": ssws,
  }

  jsonData, err := json.Marshal(data)
  if err != nil {
    fmt.Println("impossible to marshall date", err)
    return a, err
  }
  r, _ := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonData))
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
    return nil, err
  }
  err = json.Unmarshal(jsonBody, &a)
  if err != nil {
    return nil, err
  }
  return a, err
}

func (auth *OktaApiAuth) PreAuth() (map[string]interface{}, error) {
  data := map[string]string{
    "username": auth.UserCfg.Username,
    "password": auth.UserCfg.Password,
  }
  return auth.OktaReq("/authn", data)
}

func (auth *OktaApiAuth) DoAuth(fid string, stateToken string) (map[string]interface{}, error) {
  path := fmt.Sprintf("/authn/factors/%s/verify", fid)
  data := map[string]string{
    "fid": fid,
    "stateToken": stateToken,
    "passCode": auth.Passcode,
  }
  return auth.OktaReq(path, data)
}

func (auth *OktaApiAuth) Auth() (bool, error) {
  var status string
  if auth.UserCfg.Username == "" && auth.UserCfg.Password == "" {
    fmt.Println("Missing username or password for user: ",
      auth.UserCfg.Username, " (", auth.UserCfg.ClientIp, ") - ",
      "Reported username may be 'None' due to this")
    return false, nil
  }
  if auth.Passcode == "" {
    fmt.Printf("[%s] No TOTP found in password\n", auth.UserCfg.Username)
  } else {
    fmt.Println("TOTP found:", auth.UserCfg.Password)
  }
  fmt.Printf("[%s] Authenticating\n", auth.UserCfg.Username)
  retp, err := auth.PreAuth()
  if err != nil {
    fmt.Printf("[%s] Error connecting to the Okta API: %s\n", auth.UserCfg.Username, err)
    return false, err
  }

  if _, ok := retp["errorCauses"]; ok {
    fmt.Printf("[%s] pre-authentication failed: %s\n", auth.UserCfg.Username, retp["errorSummary"])
    return false, nil
  }
  if st, ok := retp["status"]; ok {
    status = st.(string)
    switch status {
    case "SUCCESS":
      fmt.Printf("[%s] allowed without MFA - refused\n", auth.UserCfg.Username)
      return false, nil
    case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
      fmt.Printf("[%s] user needs to enroll first\n", auth.UserCfg.Username)
      return false, nil
    case "MFA_REQUIRED", "MFA_CHALLENGE":
      fmt.Printf("[%s] user password validates, checking second factor\n", auth.UserCfg.Username)
      factors := retp["_embedded"].(map[string]interface{})["factors"].([]interface{})
      supportedFactorTypes := []string{"token:software:totp", "push"}
      var res map[string]interface{}
      for _, factor := range factors {
        factorType := factor.(map[string]interface{})["factorType"].(string)
        if !slices.Contains(supportedFactorTypes, factorType) {
          fmt.Println("skipping factortype ", factorType)
          continue
        }
        fmt.Println(factorType)
        if factorType != "token:software:totp" && auth.Passcode != "" {
          fmt.Println("passcode is set and factortype not token:software:totp , skipping", factorType)
          continue
        }
        fid := factor.(map[string]interface{})["id"].(string)
        stateToken := retp["stateToken"].(string)
        res, err = auth.DoAuth(fid, stateToken)
        if err != nil {
          return false, err
        }
        checkCount := 0
        for res["factorResult"] == "WAITING" {
          time.Sleep(time.Duration(auth.APICfg.MFAPushDelaySeconds)  * time.Second)
          res, err = auth.DoAuth(fid, stateToken)
          if err != nil {
            return false, err
          }
          if checkCount++; checkCount > auth.APICfg.MFAPushMaxRetries {
            fmt.Printf("[%s] User MFA push timed out\n", auth.UserCfg.Username)
            return false, nil
          }
        }
        if _, ok := res["status"]; ok {
          if res["status"] == "SUCCESS" {
            fmt.Printf("[%s] User is now authenticated with MFA via Okta API\n", auth.UserCfg.Username)
            return true, nil
          }
        }
      }
      if _, ok := res["errorCauses"]; ok {
        fmt.Println("errorCauses")
      }
      return false, nil

    default:
      fmt.Printf("Unknown preauth status: %s\n", status)
      return false, nil
    }
  }

  fmt.Printf("[%s] User is not allowed to authenticate: %s\n", auth.UserCfg.Username, status)
  return false, errors.New("NOOP")
}

func main() {
  var err error
  validator := NewOktaOpenVPNValidator()
  if err = validator.ReadConfigFile(); err != nil {
    os.Exit(1)
  }
  if err = validator.LoadEnvVars(); err != nil {
    os.Exit(1)
  }
  _ = validator.Authenticate()
  if err := validator.WriteControlFile(); err != nil {
    os.Exit(1)
  }
  //validator.run()
  if validator.isUserValid {
    os.Exit(0)
  }
  os.Exit(1)
}
