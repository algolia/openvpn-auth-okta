package validator

import (
	"errors"
	"fmt"
	"gopkg.in/ini.v1"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/oktaApiAuth"
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

var (
	cfgDefaultPaths = [4]string{
		"/etc/okta-auth-validator/api.ini",
		"/etc/openvpn/okta_openvpn.ini",
		"/etc/okta_openvpn.ini",
		"okta_openvpn.ini",
	}
	pinsetDefaultPaths = [4]string{
		"/etc/okta-auth-validator/pinset.cfg",
		"/etc/openvpn/okta_pinset.cfg",
		"/etc/okta_pinset.cfg",
		"okta_pinset.cfg",
	}
)

const passcodeLen int = 6

// PluginEnv represents the information passed to the validator when it's running as
// `Shared Object Plugin`
type PluginEnv struct {
	// ControlFile is the path to the OpenVPN auth control file
	// where the authentication result is written
	ControlFile string

	// The OpenVPN client ip address, used as `X-Forwarded-For` payload attribute
	// to the Okta API
	ClientIp string

	// The CN of the SSL certificate presented by the OpenVPN client
	CommonName string

	// The client username submitted during OpenVPN authentication
	Username string

	// The client password submitted during OpenVPN authentication
	Password string
}

type PluginMode uint8
type OktaApiAuth = oktaApiAuth.OktaApiAuth

type OktaOpenVPNValidator struct {
	configFile      string
	pinsetFile      string
	usernameTrusted bool
	isUserValid     bool
	controlFile     string
	api             *OktaApiAuth
}

func NewOktaOpenVPNValidator() *OktaOpenVPNValidator {
	api := oktaApiAuth.NewOktaApiAuth()
	return &OktaOpenVPNValidator{
		usernameTrusted: false,
		isUserValid:     false,
		controlFile:     "",
		configFile:      "",
		api:             api,
	}
}

// Setup the validator depending on the way it's invoked
func (validator *OktaOpenVPNValidator) Setup(deferred bool, args []string, pluginEnv *PluginEnv) bool {
	if err := validator.ReadConfigFile(); err != nil {
		log.Error("ReadConfigFile failure")
		if deferred {
			/*
			 * if invoked as a deferred plugin, we should always exit 0 and write result
			 * in the control file.
			 * here the validator control may not have been yet set, force it
			 */
			validator.controlFile = os.Getenv("auth_control_file")
			validator.WriteControlFile()
		}
		return false
	}

	if !deferred {
		// We're running in "Script Plugins" mode with "via-env" method
		// see "--auth-user-pass-verify cmd method" in
		//   https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
		if len(args) > 0 {
			// via-file" method
			if err := validator.LoadViaFile(args[0]); err != nil {
				log.Error("LoadViaFile failure")
				return false
			}
		} else {
			// "via-env" method
			if err := validator.LoadEnvVars(nil); err != nil {
				log.Error("LoadEnvVars failure")
				return false
			}
		}
	} else {
		// We're running in "Shared Object Plugin" mode
		// see https://openvpn.net/community-resources/using-alternative-authentication-methods/
		if err := validator.LoadEnvVars(pluginEnv); err != nil {
			log.Error("LoadEnvVars (deferred) failure")
			validator.WriteControlFile()
			return false
		}
	}

	if err := validator.LoadPinset(); err != nil {
		log.Error("LoadPinset failure")
		if deferred {
			validator.WriteControlFile()
		}
		return false
	}
	validator.parsePassword()
	if err := validator.api.InitPool(); err != nil {
		log.Error("Initpool failure")
		return false
	}
	return true
}

// Parse the password looking for an TOTP
func (validator *OktaOpenVPNValidator) parsePassword() {
	// If the password provided by the user is longer than a OTP (6 cars)
	// and the last 6 caracters are digits
	// then extract the user password (first) and the OTP
	userConfig := validator.api.UserConfig
	if len(userConfig.Password) > passcodeLen {
		last := userConfig.Password[len(userConfig.Password)-passcodeLen:]
		if _, err := strconv.Atoi(last); err == nil {
			userConfig.Passcode = last
			userConfig.Password = userConfig.Password[:len(userConfig.Password)-passcodeLen]
		} else {
			log.Debugf("[%s] No TOTP found in password", userConfig.Username)
		}
	}
}

// Read the ini file containing the API config
func (validator *OktaOpenVPNValidator) ReadConfigFile() error {
	var cfgPaths []string
	if validator.configFile == "" {
		for _, v := range cfgDefaultPaths {
			cfgPaths = append(cfgPaths, v)
		}
	} else {
		cfgPaths = append(cfgPaths, validator.configFile)
	}
	for _, cfgFile := range cfgPaths {
		if info, err := os.Stat(cfgFile); err != nil {
			continue
		} else {
			if info.IsDir() {
				continue
			} else {
				// should never fail as err would be not nil only if cfgFile is not a string (or a []byte, a Reader)
				cfg, _ := ini.Load(cfgFile)
				apiConfig := validator.api.ApiConfig
				if err := cfg.Section("OktaAPI").MapTo(apiConfig); err != nil {
					log.Errorf("Error parsing ini file: %s", err)
					return err
				}
				if apiConfig.Url == "" || apiConfig.Token == "" {
					log.Error("Missing param Url or Token")
					return errors.New("Missing param Url or Token")
				}
				validator.configFile = cfgFile
				return nil
			}
		}
	}
	log.Errorf("No ini file found in %v", cfgPaths)
	return errors.New("No ini file found")
}

// Read all allowed pubkey fingerprints for the API server from pinset file
func (validator *OktaOpenVPNValidator) LoadPinset() error {
	var pinsetPaths []string
	if validator.pinsetFile == "" {
		for _, v := range pinsetDefaultPaths {
			pinsetPaths = append(pinsetPaths, v)
		}
	} else {
		pinsetPaths = append(pinsetPaths, validator.pinsetFile)
	}
	for _, pinsetFile := range pinsetPaths {
		if info, err := os.Stat(pinsetFile); err != nil {
			continue
		} else {
			if info.IsDir() {
				continue
			} else {
				if pinset, err := os.ReadFile(pinsetFile); err != nil {
					log.Errorf("Can not read pinset config file %s", pinsetFile)
					return err
				} else {
					pinsetArray := strings.Split(string(pinset), "\n")
					cleanPinset := utils.RemoveComments(utils.RemoveEmptyStrings(pinsetArray))
					validator.api.ApiConfig.AssertPin = cleanPinset
					validator.pinsetFile = pinsetFile
					return nil
				}
			}
		}
	}
	return errors.New("No pinset file found")
}

// Get user credentials from the OpenVPN via-file
func (validator *OktaOpenVPNValidator) LoadViaFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		log.Errorf("OpenVPN via-file %s does not exists", path)
		return err
	} else {
		if viaFileBuf, err := os.ReadFile(path); err != nil {
			log.Errorf("Can not read OpenVPN via-file %s", path)
			return err
		} else {
			viaFileInfos := strings.Split(string(viaFileBuf), "\n")
			viaFileInfos = utils.RemoveEmptyStrings(viaFileInfos)
			if len(viaFileInfos) < 2 {
				log.Errorf("Invalid OpenVPN via-file %s content", path)
				return errors.New("Invalid via-file")
			}
			username := viaFileInfos[0]
			password := viaFileInfos[1]

			if !utils.CheckUsernameFormat(username) {
				log.Error("Username or CN invalid format")
				return errors.New("Invalid CN or username format")
			}

			apiConfig := validator.api.ApiConfig
			validator.usernameTrusted = true
			if apiConfig.UsernameSuffix != "" && !strings.Contains(username, "@") {
				username = fmt.Sprintf("%s@%s", username, apiConfig.UsernameSuffix)
			}
			userConfig := validator.api.UserConfig
			userConfig.Username = username
			userConfig.Password = password
			return nil
		}
	}
}

// Get user credentials and info from the environment set by OpenVPN
func (validator *OktaOpenVPNValidator) LoadEnvVars(pluginEnv *PluginEnv) error {
	if pluginEnv == nil {
		pluginEnv = &PluginEnv{
			Username:   os.Getenv("username"),
			CommonName: os.Getenv("common_name"),
			Password:   os.Getenv("password"),
			// TODO: use the local public ip as fallback
			ClientIp:    utils.GetEnv("untrusted_ip", ""),
			ControlFile: os.Getenv("auth_control_file"),
		}
	}
	validator.controlFile = pluginEnv.ControlFile

	if validator.controlFile == "" {
		log.Warning("No control file found, if using a deferred plugin auth will stall and fail.")
	}
	// if the username comes from a certificate and AllowUntrustedUsers is false:
	// user is trusted
	// otherwise BE CAREFUL, username from OpenVPN credentials will be used !
	apiConfig := validator.api.ApiConfig
	if pluginEnv.CommonName != "" && !apiConfig.AllowUntrustedUsers {
		validator.usernameTrusted = true
		pluginEnv.Username = pluginEnv.CommonName
	}

	// if username is empty, there is an issue somewhere
	if pluginEnv.Username == "" {
		log.Error("No username or CN provided")
		return errors.New("No CN or username")
	}

	if pluginEnv.Password == "" {
		log.Error("No password provided")
		return errors.New("No password")
	}

	if !utils.CheckUsernameFormat(pluginEnv.Username) {
		log.Error("Username or CN invalid format")
		return errors.New("Invalid CN or username format")
	}

	if apiConfig.AllowUntrustedUsers {
		validator.usernameTrusted = true
	}
	if apiConfig.UsernameSuffix != "" && !strings.Contains(pluginEnv.Username, "@") {
		pluginEnv.Username = fmt.Sprintf("%s@%s", pluginEnv.Username, apiConfig.UsernameSuffix)
	}

	userConfig := validator.api.UserConfig
	userConfig.Username = pluginEnv.Username
	userConfig.Password = pluginEnv.Password
	userConfig.ClientIp = pluginEnv.ClientIp
	return nil
}

// Authenticate the user against Okta API
func (validator *OktaOpenVPNValidator) Authenticate() error {
	if !validator.usernameTrusted {
		log.Infof("[%s] User is not trusted - failing", validator.api.UserConfig.Username)
		return errors.New("User not trusted")
	}
	if err := validator.api.Auth(); err == nil {
		validator.isUserValid = true
		return nil
	} else {
		return errors.New("Authentication failed")
	}
}

// Validate the OpenVPN control file and its directory permissions
func (validator *OktaOpenVPNValidator) checkControlFilePerm() error {
	if validator.controlFile == "" {
		return errors.New("Unknow control file")
	}

	if !utils.CheckNotWritable(validator.controlFile) {
		log.Errorf("Refusing to authenticate. The file %s must not be writable by non-owners.",
			validator.controlFile)
		return errors.New("control file writable by non-owners")
	}
	dirName := filepath.Dir(validator.controlFile)
	if !utils.CheckNotWritable(dirName) {
		log.Errorf("Refusing to authenticate. The directory containing the file %s must not be writable by non-owners.",
			validator.controlFile)
		return errors.New("control file dir writable by non-owners")
	}
	return nil
}

// Write the authentication result in the OpenVPN control file (only used in deferred mode)
func (validator *OktaOpenVPNValidator) WriteControlFile() {
	if err := validator.checkControlFilePerm(); err != nil {
		return
	}

	valToWrite := []byte("0")
	if validator.isUserValid {
		valToWrite = []byte("1")
	}
	if err := os.WriteFile(validator.controlFile, valToWrite, 0600); err != nil {
		log.Errorf("Failed to write to OpenVPN control file %s", validator.controlFile)
	}
}
