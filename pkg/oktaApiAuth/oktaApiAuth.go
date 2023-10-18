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
  "strconv"
  "time"

  "gopkg.in/algolia/okta-openvpn.v2/pkg/types"
  "gopkg.in/algolia/okta-openvpn.v2/pkg/utils"
)

const userAgent string = "Mozilla/5.0 (Linux; x86_64) OktaOpenVPN/2.1.0"

type OktaAPI = types.OktaAPI
type OktaUserConfig = types.OktaUserConfig


type oktaApiAuth struct {
  apiConfig  *OktaAPI
  userConfig *OktaUserConfig
  pool       *http.Client
  userAgent  string
}

func NewOktaApiAuth(apiConfig *OktaAPI, userConfig *OktaUserConfig) (auth *oktaApiAuth, err error) {
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

  auth = &oktaApiAuth{apiConfig: apiConfig, userConfig: userConfig, userAgent: userAgent}
  // If the password provided by the user is longer than a OTP (6 cars)
  // and the last 6 caracters are digits
  // then extract the user password (first) and the OTP
  if len(userConfig.Password) > passcodeLen {
    last := userConfig.Password[len(userConfig.Password)-passcodeLen:]
    if _, err := strconv.Atoi(last); err == nil {
      userConfig.Passcode = last
      userConfig.Password = userConfig.Password[:len(userConfig.Password)-passcodeLen]
    } else {
      fmt.Printf("[%s] No TOTP found in password\n", auth.userConfig.Username)
    }
  }
  
  auth.pool, err = utils.ConnectionPool(apiConfig.Url, apiConfig.AssertPin)
  if err != nil {
    return nil, err
  }
  return auth, nil
}

// Do a POST http request to the Okta API using the path and payload provided
func (auth *oktaApiAuth) oktaReq(path string, data map[string]string) (a map[string]interface{}, err error) {
  u, _ := url.ParseRequestURI(auth.apiConfig.Url)
  u.Path = fmt.Sprintf("/api/v1%s", path)

  ssws := fmt.Sprintf("SSWS %s", auth.apiConfig.Token)
  headers := map[string]string{
    "User-Agent": auth.userAgent,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": ssws,
  }
  if auth.userConfig.ClientIp != "0.0.0.0" {
    headers["X-Forwarded-For"] = auth.userConfig.ClientIp
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
func (auth *oktaApiAuth) preAuth() (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
  data := map[string]string{
    "username": auth.userConfig.Username,
    "password": auth.userConfig.Password,
  }
  return auth.oktaReq("/authn", data)
}

// Call the MFA auth Okta API endpoint
func (auth *oktaApiAuth) doAuth(fid string, stateToken string) (map[string]interface{}, error) {
  // https://developer.okta.com/docs/reference/api/authn/#verify-call-factor
  path := fmt.Sprintf("/authn/factors/%s/verify", fid)
  data := map[string]string{
    "fid": fid,
    "stateToken": stateToken,
    "passCode": auth.userConfig.Passcode,
  }
  return auth.oktaReq(path, data)
}

func (auth *oktaApiAuth) cancelAuth(stateToken string) (map[string]interface{}, error) {
  data := map[string]string{
    "stateToken": stateToken,
  }
  return auth.oktaReq("/authn/cancel", data)
}

func (auth *oktaApiAuth) Auth() (error) {
  var status string
  fmt.Printf("[%s] Authenticating\n", auth.userConfig.Username)
  retp, err := auth.preAuth()
  if err != nil {
    fmt.Printf("[%s] Error connecting to the Okta API: %s\n", auth.userConfig.Username, err)
    return err
  }

  if _, ok := retp["errorCauses"]; ok {
    fmt.Printf("[%s] pre-authentication failed: %s\n", auth.userConfig.Username, retp["errorSummary"])
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
      if auth.apiConfig.MFARequired {
        fmt.Printf("[%s] allowed without MFA and MFA is required- refused\n", auth.userConfig.Username)
        return errors.New("MFA required")
      } else {
        return nil
      }

    case "LOCKED_OUT":
      fmt.Printf("[%s] user is locked out\n", auth.userConfig.Username)
      return errors.New("User locked out")

    case "MFA_ENROLL", "MFA_ENROLL_ACTIVATE":
      fmt.Printf("[%s] user needs to enroll first\n", auth.userConfig.Username)
      _, _ = auth.cancelAuth(stateToken)
      return errors.New("Needs to enroll")

    case "MFA_REQUIRED", "MFA_CHALLENGE":
      fmt.Printf("[%s] user password validates, checking second factor\n", auth.userConfig.Username)

      factors := retp["_embedded"].(map[string]interface{})["factors"].([]interface{})
      supportedFactorTypes := []string{"token:software:totp", "push"}
      var res map[string]interface{}

      // When a TOTP is provided ensure that the proper Okta factor id used first, fallback to push
      // use first push when TOTP is empty
      var preferedFactor string = "push"
      if auth.userConfig.Passcode != "" {
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
          time.Sleep(time.Duration(auth.apiConfig.MFAPushDelaySeconds)  * time.Second)
          res, err = auth.doAuth(fid, stateToken)
          if err != nil {
            _, _ = auth.cancelAuth(stateToken)
            return err
          }
          if checkCount++; checkCount > auth.apiConfig.MFAPushMaxRetries {
            fmt.Printf("[%s] User MFA push timed out\n", auth.userConfig.Username)
            _, _ = auth.cancelAuth(stateToken)
            return errors.New("MFA timeout")
          }
        }
        if _, ok := res["status"]; ok {
          if res["status"] == "SUCCESS" {
            fmt.Printf("[%s] User is now authenticated with MFA via Okta API\n", auth.userConfig.Username)
            return nil
          } else {
            fmt.Printf("[%s] User MFA push failed: %s\n", auth.userConfig.Username, res["factorResult"])
            _, _ = auth.cancelAuth(stateToken)
            return errors.New("MFA failed")
          }
        }
      }
      if _, ok := res["errorCauses"]; ok {
        cause := res["errorCauses"].([]interface{})[0]
        errorSummary := cause.(map[string]interface{})["errorSummary"].(string)
        fmt.Printf("[%s] User MFA token authentication failed: %s\n", auth.userConfig.Username, errorSummary)
        return errors.New(errorSummary)
      }
      return errors.New("Unknown error")

    default:
      fmt.Printf("Unknown preauth status: %s\n", status)
      return errors.New("Unknown preauth status")
    }
  }

  fmt.Printf("[%s] User is not allowed to authenticate: %s\n", auth.userConfig.Username, status)
  return errors.New("Not allowed")
}

