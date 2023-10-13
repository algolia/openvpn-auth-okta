package utils

import (
  "crypto/sha256"
  "crypto/tls"
  "crypto/x509"
  "encoding/base64"
  "fmt"
  "net/http"
  "net/url"
  "regexp"
  "slices"
  "time"
  "os"
)
 

func GetEnv(key, fallback string) string {
  if value, ok := os.LookupEnv(key); ok {
    if value == "" {
      return fallback
    }
    return value
  }
  return fallback
}

func CheckUsernameFormat(name string) bool {
  /* OpenVPN doc says:
  To protect against a client passing a maliciously formed username or password string,
  the username string must consist only of these characters:
  alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
  */
  match, err := regexp.MatchString(`^([[:alnum:]]|[_\-\.@])*$`, name);
  if err != nil || !match {
    return false
  }
  return true
}

// Check that path is not group or other writable
func CheckNotWritable(path string) bool {
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

func RemoveEmptyStrings(s []string) []string {
  var r []string
  for _, str := range s {
    if str != "" {
      r = append(r, str)
    }
  }
  return r
}

// Prepare an http client with the proper TLS config
// validate the server public key against our list of pinned key fingerprint
func ConnectionPool(oktaURL string, pinset []string) (*http.Client, error) {
  if rawURL, err := url.Parse(oktaURL); err != nil {
    return nil, err
  } else {
    port := rawURL.Port()
    if port == "" {
      port="443"
    }
    // Connect to the server, fetch its public key and validate it against the
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
            return nil, fmt.Errorf("Server pubkey does not match pinned keys")
        }
      }
    }
  }

  tlsCfg := &tls.Config{
    InsecureSkipVerify: false,
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
      // TLS 1.2 safe cipher suites
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
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

