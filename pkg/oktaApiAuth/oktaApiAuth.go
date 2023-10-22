package oktaApiAuth

import (
  "bytes"
  "io"
  "encoding/json"
  "errors"
  "fmt"
  "net/http"
  "net/url"
  "slices"
  "sort"
  "time"

  "gopkg.in/algolia/openvpn-auth-okta.v2/pkg/utils"
)

const userAgent string = "Mozilla/5.0 (Linux; x86_64) OktaOpenVPN/2.1.0"

// Contains the configuration for the Okta API connection
// Those configuration options are read from okta_openvpn.ini
type OktaAPIConfig struct {
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

type OktaApiAuth struct {
  ApiConfig  *OktaAPIConfig
  UserConfig *OktaUserConfig
  pool       *http.Client
  userAgent  string
}

func NewOktaApiAuth() (*OktaApiAuth) {
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

  return &OktaApiAuth{
    ApiConfig: &OktaAPIConfig{
      AllowUntrustedUsers: false,
      MFARequired: false,
      MFAPushMaxRetries: 20,
      MFAPushDelaySeconds: 3,
    },
    UserConfig: &OktaUserConfig{},
    userAgent: userAgent,
  }
}

func (auth *OktaApiAuth) InitPool() (err error) {
  auth.pool, err = utils.ConnectionPool(auth.ApiConfig.Url, auth.ApiConfig.AssertPin)
  if err != nil {
    return err
  }
  return nil
}

func (auth *OktaApiAuth) Pool() (*http.Client) {
  return auth.pool
}

// Do a POST http request to the Okta API using the path and payload provided
func (auth *OktaApiAuth) oktaReq(path string, data map[string]string) (a map[string]interface{}, err error) {
  u, _ := url.ParseRequestURI(auth.ApiConfig.Url)
  u.Path = fmt.Sprintf("/api/v1%s", path)

  ssws := fmt.Sprintf("SSWS %s", auth.ApiConfig.Token)
  headers := map[string]string{
    "User-Agent": auth.userAgent,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": ssws,
  }
  if auth.UserConfig.ClientIp != "0.0.0.0" {
    headers["X-Forwarded-For"] = auth.UserConfig.ClientIp
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
  resp, err := auth.pool.Do(r)
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
func (auth *OktaApiAuth) preAuth() (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
  data := map[string]string{
    "username": auth.UserConfig.Username,
    "password": auth.UserConfig.Password,
  }
  return auth.oktaReq("/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *OktaApiAuth) doAuth(fid string, stateToken string) (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
  path := fmt.Sprintf("/authn/factors/%s/verify", fid)
  data := map[string]string{
    "fid": fid,
    "stateToken": stateToken,
    "passCode": auth.UserConfig.Passcode,
  }
  return auth.oktaReq(path, data)
}

func (auth *OktaApiAuth) cancelAuth(stateToken string) (map[string]interface{}, error) {
  data := map[string]string{
    "stateToken": stateToken,
  }
  return auth.oktaReq("/authn/cancel", data)
}

func (auth *OktaApiAuth) Auth() (error) {
  var status string
  fmt.Printf("[%s] Authenticating\n", auth.UserConfig.Username)
  retp, err := auth.preAuth()
  if err != nil {
    fmt.Printf("[%s] Error connecting to the Okta API: %s\n", auth.UserConfig.Username, err)
    return err
  }

  if _, ok := retp["errorCauses"]; ok {
    fmt.Printf("[%s] pre-authentication failed: %s\n", auth.UserConfig.Username, retp["errorSummary"])
    return errors.New("pre-authentication failed")
  }
  if st, ok := retp["status"]; ok {
    status = st.(string)
    stateToken := ""
    if tok, ok := retp["stateToken"]; ok {
      stateToken = tok.(string)
    }

    switch status {
    case "SUCCESS":
      if auth.ApiConfig.MFARequired {
        fmt.Printf("[%s] allowed without MFA and MFA is required - rejected\n", auth.UserConfig.Username)
        return errors.New("MFA required")
      } else {
        return nil
      }

    case "LOCKED_OUT":
      fmt.Printf("[%s] user is locked out\n", auth.UserConfig.Username)
      return errors.New("User locked out")

    case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
      fmt.Printf("[%s] user needs to enroll first\n", auth.UserConfig.Username)
      _, _ = auth.cancelAuth(stateToken)
      return errors.New("Needs to enroll")

    case "MFA_REQUIRED", "MFA_CHALLENGE":
      fmt.Printf("[%s] user password validates, checking second factor\n", auth.UserConfig.Username)

      factors := retp["_embedded"].(map[string]interface{})["factors"].([]interface{})
      supportedFactorTypes := []string{"token:software:totp", "push"}
      var res map[string]interface{}

      // When a TOTP is provided ensure that the proper Okta factor id used first, fallback to push
      // use first push when TOTP is empty
      var preferedFactor string = "push"
      if auth.UserConfig.Passcode != "" {
        preferedFactor = "token:software:totp"
      }
      sort.Slice(factors, func(i, j int) bool {
        return factors[i].(map[string]interface{})["factorType"].(string) == preferedFactor
      })

      for _, factor := range factors {
        factorType := factor.(map[string]interface{})["factorType"].(string)
        if !slices.Contains(supportedFactorTypes, factorType) {
          fmt.Printf("Unsupported factortype: %s, skipping\n", factorType)
          continue
        }
        fid := factor.(map[string]interface{})["id"].(string)
        res, err = auth.doAuth(fid, stateToken)
        if err != nil {
          _, _ = auth.cancelAuth(stateToken)
          return err
        }
        checkCount := 0
        for res["factorResult"] == "WAITING" {
          time.Sleep(time.Duration(auth.ApiConfig.MFAPushDelaySeconds)  * time.Second)
          res, err = auth.doAuth(fid, stateToken)
          if err != nil {
            _, _ = auth.cancelAuth(stateToken)
            return err
          }
          if checkCount++; checkCount > auth.ApiConfig.MFAPushMaxRetries {
            fmt.Printf("[%s] User MFA push timed out\n", auth.UserConfig.Username)
            _, _ = auth.cancelAuth(stateToken)
            return errors.New("MFA timeout")
          }
        }
        if _, ok := res["status"]; ok {
          if res["status"] == "SUCCESS" {
            fmt.Printf("[%s] User is now authenticated with MFA via Okta API\n", auth.UserConfig.Username)
            return nil
          } else {
            fmt.Printf("[%s] User MFA push failed: %s\n", auth.UserConfig.Username, res["factorResult"])
            _, _ = auth.cancelAuth(stateToken)
            return errors.New("MFA failed")
          }
        }
      }
      if _, ok := res["errorCauses"]; ok {
        cause := res["errorCauses"].([]interface{})[0]
        errorSummary := cause.(map[string]interface{})["errorSummary"].(string)
        fmt.Printf("[%s] User MFA token authentication failed: %s\n", auth.UserConfig.Username, errorSummary)
        return errors.New(errorSummary)
      }
      return errors.New("Unknown error")

    default:
      fmt.Printf("Unknown preauth status: %s\n", status)
      return errors.New("Unknown preauth status")
    }
  }

  fmt.Printf("[%s] User is not allowed to authenticate: %s\n", auth.UserConfig.Username, status)
  return errors.New("Not allowed")
}

