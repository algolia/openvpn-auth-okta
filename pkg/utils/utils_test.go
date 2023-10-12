package utils

import (
  "crypto/tls"
  "fmt"
  "net/http"
  "testing"
  "time"

  "github.com/stretchr/testify/assert"
)

// validPinset has been computed using:
/*
cat testing/fixtures/server.crt |\
  openssl x509 -noout -pubkey |\
  openssl rsa  -pubin -outform der 2>/dev/null |\
  openssl dgst -sha256 -binary | base64
*/
const (
  tlsEndpoint   string = "127.0.0.1:1443"
  validPinset   string = "j69yToSVkR6G7RKEc0qvsA6MysH+luI3wBIihDA20nI="
  invalidPinset string = "ABCDEF"
)

type tlsTest struct {
  testName string
  pinset   []string
  res      func(t assert.TestingT, object interface{}, msgAndArgs ...interface{}) bool
}

type usernameTest struct {
  testName string
  username string
  res      bool
}

func TestCheckUsernameFormat(t *testing.T) {
  tests := []usernameTest{
    {
      "Test valid username - success",
      "dade.murphy@example.com",
      true,
    },
    {
      "Test invalid username - failure",
      "dade.*murphy/",
      false,
    },
  }
  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      res := CheckUsernameFormat(test.username)
      assert.Equal(t, test.res, res)
    })
  }
}

func startTLS(t *testing.T) {
  t.Helper()

  mux := http.NewServeMux()
  mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("This is an example server.\n"))
  })
  cfg := &tls.Config{MinVersion: tls.VersionTLS12}
  s := http.Server{
    Addr: tlsEndpoint,
    Handler: mux,
    TLSConfig: cfg,
    ReadTimeout: 1*time.Second,
    WriteTimeout: 1*time.Second,
  }
  err := s.ListenAndServeTLS("../../testing/fixtures/server.crt",
    "../../testing/fixtures/server.key")
  assert.NoError(t, err)
  t.Cleanup(func() { _ = s.Close() })
}

func TestConnectionPool(t *testing.T) {
  tests := []tlsTest{
    {
      "Valid pinset",
      []string{validPinset},
      assert.Nil,
    },
    {
      "Invalid pinset",
      []string{invalidPinset},
      assert.NotNil,
    },
  }
  go func(){
    startTLS(t)
  }()

  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      _, err := ConnectionPool(fmt.Sprintf("https://%s", tlsEndpoint), test.pinset)
      test.res(t, err)
    })
  }
}
