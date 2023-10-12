package validator

import (
  "fmt"
  "io/fs"
  "os"
  "slices"
  "testing"

  "github.com/stretchr/testify/assert"
)

const (
  // used in TestLoadPinset
  pin         string = "SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="
  // used in TestWriteControlFile
  controlFile string = "../../testing/fixtures/validator/control_file"
)

// used in TestReadConfigFile, TestLoadPinset
type testCfgFile struct {
  testName string
  path     string
  err      error
}

type testViaFile struct{
  testName         string
  path             string
  usernameSuffix   string
  expectedUsername string
  expectedPassword string
  err              error
}

type testEnvVar struct{
  testName            string
  usernameSuffix      string
  allowUntrustedUsers bool
  expectedTrusted     bool
  expectedUsername    string
  env                 map[string]string
  err                 error
}

type testControlFile struct {
  testName string
  path     string
  mode     fs.FileMode
  err      error
}

type testWriteFile struct {
  testName  string 
  userValid bool
  expected  string
}

func TestReadConfigFile(t *testing.T) {
  tests := []testCfgFile{
    {
      "Test valid config file - success",
      "../../testing/fixtures/validator/valid.ini",
      nil,
    },
    {
      "Test invalid config file - failure",
      "../../testing/fixtures/validator/invalid.ini",
      fmt.Errorf("Missing param Url or Token"),
    },
    {
      "Test missing config file - failure",
      "MISSING",
      fmt.Errorf("No ini file found"),
    },
  }

  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      v := NewOktaOpenVPNValidator()
      v.configFile = test.path
      err := v.ReadConfigFile()
      if test.err == nil {
        assert.Nil(t, err)
      } else {
        assert.Equal(t, err.Error(), test.err.Error())
      }
    })
  }
}

func TestLoadPinset(t *testing.T) {
  tests := []testCfgFile{
    {
      "Test pinset file - success",
      "../../testing/fixtures/validator/valid.cfg",
      nil,
    },
    {
      "Test missing file - failure",
      "MISSING",
      fmt.Errorf("No pinset file found"),
    },
  }

  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      v := NewOktaOpenVPNValidator()
      v.apiConfig = &OktaAPI{}
      v.pinsetFile = test.path

      err := v.LoadPinset()
      if test.err == nil {
        assert.Nil(t, err)
        assert.True(t, slices.Contains(v.apiConfig.AssertPin, pin))
      } else {
        assert.Equal(t, err.Error(), test.err.Error())
      }
    })
  }
}

func TestLoadViaFile(t *testing.T) {
  tests := []testViaFile{
    {
      "Test valid via file with suffix - success",
      "../../testing/fixtures/validator/valid_viafile.cfg",
      "example.com",
      "dade.murphy@example.com",
      "password",
      nil,
    },
    {
      "Test valid via file without suffix - success",
      "../../testing/fixtures/validator/valid_viafile.cfg",
      "",
      "dade.murphy",
      "password",
      nil,
    },
    {
      "Test invalid via file - failure",
      "../../testing/fixtures/validator/invalid_viafile.cfg",
      "",
      "dade.murphy",
      "password",
      fmt.Errorf("Invalid via-file"),
    },

    {
      "Test missing via file - failure",
      "MISSING",
      "",
      "dade.murphy",
      "password",
      fmt.Errorf("stat MISSING: no such file or directory"),
    },

  }
  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      v := NewOktaOpenVPNValidator()
      v.apiConfig = &OktaAPI{
          UsernameSuffix: test.usernameSuffix,
        }
      err := v.LoadViaFile(test.path)
      if test.err == nil {
        assert.Nil(t, err)
        assert.NotNil(t, v.userConfig)
        assert.Equal(t, v.userConfig.Username, test.expectedUsername)
        assert.Equal(t, v.userConfig.Password, test.expectedPassword)
      } else {
        assert.Equal(t, err.Error(), test.err.Error())
      }
    })
  }
}

func setEnv(e map[string]string) {
  for k, v := range e {
    os.Setenv(k, v)
  }
}

func unsetEnv(e map[string]string) {
  for k := range e {
    os.Unsetenv(k)
  }
}

func TestLoadEnvVars(t *testing.T) {
  tests := []testEnvVar{
    {
      "Test username/allowUntrustedUsers/usernameSuffix - succes",
      "example.com",
      true,
      true,
      "dade.murphy@example.com",
      map[string]string{
        "username": "dade.murphy",
        "common_name": "",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      nil,
    },
    {
      "Test username/!allowUntrustedUsers/usernameSuffix - success",
      "example.com",
      false,
      false,
      "dade.murphy@example.com",
      map[string]string{
        "username": "dade.murphy",
        "common_name": "",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      nil,
    },
    {
      "Test common_name/!allowUntrustedUsers/usernameSuffix - success",
      "example.com",
      false,
      true,
      "dade.murphy2@example.com",
      map[string]string{
        "username": "dade.murphy",
        "common_name": "dade.murphy2",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      nil,
    },
    {
      "Test username/common_name/allowUntrustedUsers/usernameSuffix - success",
      "example.com",
      true,
      true,
      "dade.murphy@example.com",
      map[string]string{
        "username": "dade.murphy",
        "common_name": "dade.murphy2",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      nil,
    },
    {
      "Test empty username/common_name - failure",
      "example.com",
      false,
      false,
      "dade.murphy@example.com",
      map[string]string{
        "username": "",
        "common_name": "",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      fmt.Errorf("Invalid CN or username"),
    },
    {
      "Test invalid username/common_name - failure",
      "example.com",
      false,
      false,
      "dade.murphy@example.com",
      map[string]string{
        "username": "dade.murphy*",
        "common_name": "",
        "password": "password",
        "untrusted_ip": "1.2.3.4",
      },
      fmt.Errorf("Invalid CN or username format"),
    },
  }
  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      setEnv(test.env)
      v := NewOktaOpenVPNValidator()
      v.apiConfig = &OktaAPI{
          UsernameSuffix: test.usernameSuffix,
          AllowUntrustedUsers: test.allowUntrustedUsers,
        }
      err := v.LoadEnvVars()
      unsetEnv(test.env)
      assert.Equal(t, v.usernameTrusted, test.expectedTrusted)
      if v.userConfig != nil {
        assert.Equal(t, v.userConfig.Username, test.expectedUsername)
      }
      if test.err == nil {
        assert.Nil(t, err)
      } else {
        assert.Equal(t, test.err.Error(), err.Error())
      }
    })
  }
}

// Authenticate() already done in oktaApiAuth and Load*

func TestCheckControlFilePerm(t *testing.T) {
  tests := []testControlFile{
    {
      "Test empty control file path - failure",
      "",
      0600,
      fmt.Errorf("Unknow control file"),
    },
    {
      "Test valid control file permissions - success",
      "../../testing/fixtures/validator/valid_control_file",
      0600,
      nil,
    },
    {
      "Test invalid control file permissions - success",
      "../../testing/fixtures/validator/invalid_control_file",
      0660,
      fmt.Errorf("control file writable by non-owners"),
    },
  }
  for _, test := range tests {
    t.Run(test.testName, func(t *testing.T) {
      v := NewOktaOpenVPNValidator()
      if test.path != "" {
        v.controlFile = test.path
        _, _ = os.Create(test.path)
        defer func() { _ = os.Remove(test.path) }()
        _ = os.Chmod(test.path, test.mode)
      }
      err := v.checkControlFilePerm()
      if test.err == nil {
        assert.Nil(t, err)
      } else {
        assert.Equal(t, test.err.Error(), err.Error())
      }
    })
  }
}

func TestWriteControlFile(t *testing.T) {
  tests := []testWriteFile{
    {
      "Test valid user - success",
      true,
      "1",
    },
    {
      "Test invalid user - success",
      false,
      "0",
    },
  }
  for _, test := range tests {
    _, _ = os.Create(controlFile)
    defer func() { _ = os.Remove(controlFile) }()
    _ = os.Chmod(controlFile, 0600)
    t.Run(test.testName, func(t *testing.T) {
      v := NewOktaOpenVPNValidator()
      v.controlFile = controlFile
      v.isUserValid = test.userValid
      v.WriteControlFile()
      ctrlValue, _ := os.ReadFile(controlFile)
      assert.Equal(t, test.expected, string(ctrlValue))
    })
  }
}
