package validator

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

const (
	// used in TestWriteControlFile
	controlFile  string = "../../testing/fixtures/validator/control_file"
	oktaEndpoint string = "https://example.oktapreview.com"
	token        string = "12345"
)

var setupEnv = map[string]string{
	"username":          "dade.murphy",
	"common_name":       "",
	"password":          "password",
	"untrusted_ip":      "1.2.3.4",
	"auth_control_file": controlFile,
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
			err := v.Setup(true, true, nil, nil)
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
			ret := v.Setup(test.deferred, true, test.args, nil)
			unsetEnv(test.env)
			assert.Equal(t, test.ret, ret)
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
