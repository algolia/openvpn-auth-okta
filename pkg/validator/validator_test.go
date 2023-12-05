package validator

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
	"gopkg.in/h2non/gock.v1"
)

const (
	// used in TestLoadPinset
	pin string = "SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE="
	// used in TestWriteControlFile
	controlFile  string = "../../testing/fixtures/validator/control_file"
	oktaEndpoint string = "https://example.oktapreview.com"
	token        string = "12345"
)

// used in TestReadConfigFile, TestLoadPinset
type testCfgFile struct {
	testName string
	path     string
	link     string
	err      error
}

type testViaFile struct {
	testName         string
	path             string
	usernameSuffix   string
	expectedUsername string
	expectedPassword string
	err              error
}

type testEnvVar struct {
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

type testSetup struct {
	testName   string
	cfgFile    string
	pinsetFile string
	deferred   bool
	env        map[string]string
	args       []string
	ret        bool
}

type authRequest struct {
	path             string
	payload          map[string]string
	httpStatus       int
	jsonResponseFile string
}

type testAuthenticate struct {
	testName    string
	cfgFile     string
	pinsetFile  string
	userTrusted bool
	requests    []authRequest
	ret         bool
	err         error
}

var setupEnv = map[string]string{
	"username":          "dade.murphy",
	"common_name":       "",
	"password":          "password",
	"untrusted_ip":      "1.2.3.4",
	"auth_control_file": controlFile,
}

func TestAuthenticate(t *testing.T) {
	defer gock.Off()
	//gock.Observe(gock.DumpRequest)
	tests := []testAuthenticate{
		{
			"Untrusted user - false",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			false,
			fmt.Errorf("User not trusted"),
		},

		{
			"Valid user - true",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{
						"username": fmt.Sprintf("%s@example.com", setupEnv["username"]),
						"password": setupEnv["password"],
					},
					http.StatusOK,
					"preauth_success_without_mfa.json",
				},
			},
			true,
			nil,
		},

		{
			"Invalid user - true",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			[]authRequest{
				{
					"/api/v1/authn",
					map[string]string{
						"username": fmt.Sprintf("%s@example.com", setupEnv["username"]),
						"password": setupEnv["password"],
					},
					http.StatusUnauthorized,
					"preauth_invalid_token.json",
				},
			},
			false,
			fmt.Errorf("Authentication failed"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			gock.Clean()
			gock.Flush()

			for _, req := range test.requests {
				reqponseFile := fmt.Sprintf("../../testing/fixtures/oktaApi/%s", req.jsonResponseFile)
				l := gock.New(oktaEndpoint)
				l = l.Post(req.path).
					MatchHeader("Authorization", fmt.Sprintf("SSWS %s", token)).
					MatchHeader("X-Forwarded-For", setupEnv["untrusted_ip"]).
					MatchType("json").
					JSON(req.payload)
				l.Reply(req.httpStatus).
					File(reqponseFile)
			}

			setEnv(setupEnv)
			v := NewOktaOpenVPNValidator()
			v.configFile = test.cfgFile
			v.pinsetFile = test.pinsetFile
			err := v.Setup(true, nil, nil)
			unsetEnv(setupEnv)
			assert.True(t, err)
			v.usernameTrusted = test.userTrusted
			v.api.ApiConfig.MFARequired = false
			gock.InterceptClient(v.api.Pool())
			gock.DisableNetworking()
			err2 := v.Authenticate()
			assert.Equal(t, test.ret, v.isUserValid)
			if test.err == nil {
				assert.Nil(t, err2)
			} else {
				assert.Equal(t, test.err.Error(), err2.Error())
			}
		})
	}
}

func TestSetup(t *testing.T) {
	tests := []testSetup{
		{
			"Invalid url in config file / deferred - false",
			"../../testing/fixtures/validator/invalid_url.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / deferred - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Valid config file / valid env / deferred - true",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			setupEnv,
			nil,
			true,
		},
		{
			"Invalid env / deferred - false",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			true,
			map[string]string{"auth_control_file": controlFile},
			nil,
			false,
		},
		{
			"Invalid pinset / deferred - false",
			"../../testing/fixtures/validator/valid.ini",
			"MISSING",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / via-env - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			setupEnv,
			nil,
			false,
		},
		{
			"Valid config file / valid env / via-env - true",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			setupEnv,
			nil,
			true,
		},
		{
			"Invalid env / via-env - false",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			map[string]string{"auth_control_file": controlFile},
			nil,
			false,
		},
		{
			"Invalid pinset / via-env - false",
			"../../testing/fixtures/validator/valid.ini",
			"MISSING",
			true,
			setupEnv,
			nil,
			false,
		},
		{
			"Invalid config file / via-file - false",
			"../../testing/fixtures/validator/invalid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			false,
		},
		{
			"Valid config file / valid via-file / via-env - true",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			true,
		},
		{
			"Invalid via-file / via-file - false",
			"../../testing/fixtures/validator/valid.ini",
			"../../testing/fixtures/validator/valid.cfg",
			false,
			nil,
			[]string{"../../testing/fixtures/validator/invalid_viafile.cfg"},
			false,
		},
		{
			"Invalid pinset / via-env - false",
			"../../testing/fixtures/validator/valid.ini",
			"MISSING",
			true,
			nil,
			[]string{"../../testing/fixtures/validator/valid_viafile.cfg"},
			false,
		},
	}

	_, _ = os.Create(controlFile)
	defer func() { _ = os.Remove(controlFile) }()

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			setEnv(test.env)
			v := NewOktaOpenVPNValidator()
			v.configFile = test.cfgFile
			v.pinsetFile = test.pinsetFile
			ret := v.Setup(test.deferred, test.args, nil)
			unsetEnv(test.env)
			assert.Equal(t, test.ret, ret)
		})
	}
}

func TestCheckPasscode(t *testing.T) {
	t.Run("Parse password with passcode", func(t *testing.T) {
		setEnv(setupEnv)
		v := NewOktaOpenVPNValidator()
		_ = v.LoadEnvVars(nil)
		v.api.UserConfig.Password = "password123456"
		unsetEnv(setupEnv)
		v.parsePassword()
		assert.Equal(t, "password", v.api.UserConfig.Password)
		assert.Equal(t, "123456", v.api.UserConfig.Passcode)
	})
}

func TestReadConfigFile(t *testing.T) {
	tests := []testCfgFile{
		{
			"Valid config file - success",
			"../../testing/fixtures/validator/valid.ini",
			"",
			nil,
		},
		{
			"Valid config file link - success",
			"",
			"../../testing/fixtures/validator/valid.ini",
			nil,
		},
		{
			"Invalid config file - failure",
			"../../testing/fixtures/validator/invalid.ini",
			"",
			fmt.Errorf("Missing param Url or Token"),
		},
		{
			"Missing config file - failure",
			"MISSING",
			"",
			fmt.Errorf("No ini file found"),
		},
		{
			"Config file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			fmt.Errorf("No ini file found"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.configFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "api.ini")
			}
			err := v.ReadConfigFile()
			if test.path == "" {
				_ = os.Remove("api.ini")
			}
			if test.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

func TestLoadPinset(t *testing.T) {
	tests := []testCfgFile{
		{
			"Valid pinset file - success",
			"../../testing/fixtures/validator/valid.cfg",
			"",
			nil,
		},
		{
			"Valid pinset link - success",
			"",
			"../../testing/fixtures/validator/valid.cfg",
			nil,
		},
		{
			"Missing pinset file - failure",
			"MISSING",
			"",
			fmt.Errorf("No pinset file found"),
		},
		{
			"Pinset file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			fmt.Errorf("No pinset file found"),
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.api = oktaApiAuth.NewOktaApiAuth()
			v.pinsetFile = test.path
			if test.path == "" {
				_ = os.Symlink(test.link, "pinset.cfg")
			}
			err := v.LoadPinset()
			if test.path == "" {
				_ = os.Remove("pinset.cfg")
			}
			if test.err == nil {
				assert.Nil(t, err)
				assert.True(t, slices.Contains(v.api.ApiConfig.AssertPin, pin))
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

func TestLoadViaFile(t *testing.T) {
	tests := []testViaFile{
		{
			"Valid via file with suffix - success",
			"../../testing/fixtures/validator/valid_viafile.cfg",
			"example.com",
			"dade.murphy@example.com",
			"password",
			nil,
		},
		{
			"Valid via file without suffix - success",
			"../../testing/fixtures/validator/valid_viafile.cfg",
			"",
			"dade.murphy",
			"password",
			nil,
		},
		{
			"Invalid via file - failure",
			"../../testing/fixtures/validator/invalid_viafile.cfg",
			"",
			"dade.murphy",
			"password",
			fmt.Errorf("Invalid via-file"),
		},
		{
			"Invalid username in via file - failure",
			"../../testing/fixtures/validator/invalid_username_viafile.cfg",
			"",
			"dade.murphy*",
			"password",
			fmt.Errorf("Invalid CN or username format"),
		},
		{
			"Missing via file - failure",
			"MISSING",
			"",
			"dade.murphy",
			"password",
			fmt.Errorf("stat MISSING: no such file or directory"),
		},
		{
			"Via file is a dir - failure",
			"../../testing/fixtures/validator/",
			"",
			"dade.murphy",
			"password",
			fmt.Errorf("read ../../testing/fixtures/validator/: is a directory"),
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.api = oktaApiAuth.NewOktaApiAuth()
			v.api.ApiConfig.UsernameSuffix = test.usernameSuffix
			err := v.LoadViaFile(test.path)
			if test.err == nil {
				assert.Nil(t, err)
				assert.NotNil(t, v.api.UserConfig)
				assert.Equal(t, test.expectedUsername, v.api.UserConfig.Username)
				assert.Equal(t, test.expectedPassword, v.api.UserConfig.Password)
			} else {
				assert.Equal(t, test.err.Error(), err.Error())
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
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			nil,
		},
		{
			"Test username/no password - failure",
			"example.com",
			true,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "",
				"untrusted_ip": "1.2.3.4",
			},
			fmt.Errorf("No password"),
		},
		{
			"Test username/!allowUntrustedUsers/usernameSuffix - success",
			"example.com",
			false,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy",
				"common_name":  "",
				"password":     "password",
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
				"username":     "dade.murphy",
				"common_name":  "dade.murphy2",
				"password":     "password",
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
				"username":     "dade.murphy",
				"common_name":  "dade.murphy2",
				"password":     "password",
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
				"username":     "",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			fmt.Errorf("No CN or username"),
		},
		{
			"Test invalid username/common_name - failure",
			"example.com",
			false,
			false,
			"dade.murphy@example.com",
			map[string]string{
				"username":     "dade.murphy*",
				"common_name":  "",
				"password":     "password",
				"untrusted_ip": "1.2.3.4",
			},
			fmt.Errorf("Invalid CN or username format"),
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			setEnv(test.env)
			v := NewOktaOpenVPNValidator()
			v.api.ApiConfig.UsernameSuffix = test.usernameSuffix
			v.api.ApiConfig.AllowUntrustedUsers = test.allowUntrustedUsers
			err := v.LoadEnvVars(nil)
			unsetEnv(test.env)
			assert.Equal(t, test.expectedTrusted, v.usernameTrusted)
			if test.err == nil {
				assert.Nil(t, err)
				assert.Equal(t, test.expectedUsername, v.api.UserConfig.Username)
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
		{
			"Test invalid control file dir permissions - success",
			"../../testing/fixtures/validator/invalid_ctrlfile_dir_perm/ctrl",
			0600,
			fmt.Errorf("control file dir writable by non-owners"),
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			if test.path != "" {
				v.controlFile = test.path
				_, _ = os.Create(test.path)
				defer func() { _ = os.Remove(test.path) }()
				// This is crapy but git does not group write bit ...
				if dirName := filepath.Base(filepath.Dir(test.path)); dirName == "invalid_ctrlfile_dir_perm" {
					_ = os.Chmod(filepath.Dir(test.path), 0770)
				}
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
		{
			"Test non writable control file - success",
			false,
			"",
		},
	}
	var mode fs.FileMode
	for _, test := range tests {
		_, _ = os.Create(controlFile)
		defer func() { _ = os.Remove(controlFile) }()
		if test.expected == "" {
			mode = 0660
		} else {
			mode = 0600
		}
		_ = os.Chmod(controlFile, mode)
		t.Run(test.testName, func(t *testing.T) {
			v := NewOktaOpenVPNValidator()
			v.controlFile = controlFile
			v.isUserValid = test.userValid
			v.WriteControlFile()
			ctrlValue, _ := os.ReadFile(controlFile)
			if test.expected == "" {
				i, _ := os.Stat(controlFile)
				size := i.Size()
				assert.Equal(t, size, int64(0))
			} else {
				assert.Equal(t, test.expected, string(ctrlValue))
			}
		})
	}
}
