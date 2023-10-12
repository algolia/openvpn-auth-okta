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
  tlsHost       string = "127.0.0.1"
  tlsPort       string = "1443"
  validPinset   string = "j69yToSVkR6G7RKEc0qvsA6MysH+luI3wBIihDA20nI="
  invalidPinset string = "ABCDEF"
)

type tlsTest struct {
  testName string
  host     string
  port     string
  pinset   []string
  err      error
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
    Addr: fmt.Sprintf("%s:%s", tlsHost, tlsPort),
    Handler: mux,
    TLSConfig: cfg,
    ReadTimeout: 1*time.Second,
    WriteTimeout: 1*time.Second,
  }
  err := s.ListenAndServeTLS("../../testing/fixtures/utils/server.crt",
    "../../testing/fixtures/utils/server.key")
  assert.NoError(t, err)
  t.Cleanup(func() { _ = s.Close() })
}

func TestConnectionPool(t *testing.T) {
  invalidHost := "invalid{host"
  invalidHostErr := fmt.Sprintf("parse \"https://%s:%s\": invalid character \"{\" in host name",
    invalidHost,
    tlsPort)

  tests := []tlsTest{
    {
      "Test valid pinset",
      tlsHost,
      tlsPort,
      []string{validPinset},
      nil,
    },
    {
      "Test invalid pinset",
      tlsHost,
      tlsPort,
      []string{invalidPinset},
      fmt.Errorf("Server pubkey does not match pinned keys"),
    },
    {
      "Test unreachable host",
      tlsHost,
      "1444",
      []string{},
      fmt.Errorf(fmt.Sprintf("dial tcp %s:1444: connect: connection refused", tlsHost)),
    },
    {
      "Test invalid url",
      invalidHost,
      tlsPort,
      []string{},
      fmt.Errorf(invalidHostErr),
    },

  }
  go func(){
    startTLS(t)
  }()

  time.Sleep(1 * time.Second)
  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      _, err := ConnectionPool(fmt.Sprintf("https://%s:%s", test.host, test.port), test.pinset)
      if test.err == nil {
        if err != nil {
          t.Logf(err.Error())
        }
        assert.Nil(t, err)
      } else {
        assert.Equal(t, test.err.Error(), err.Error())
      }
    })
  }
}
