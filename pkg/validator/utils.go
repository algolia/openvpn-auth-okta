package validator

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/t-tomalak/logrus-easy-formatter"
)

const passcodeLen int = 6

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
			log.Debugf("no TOTP found in password")
		}
	}
}

// get an env var by its name, returns the fallback if not found
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// check that username respects OpenVPN recomandation
func checkUsernameFormat(name string) bool {
	/* OpenVPN doc says:
	To protect against a client passing a maliciously formed username or password string,
	the username string must consist only of these characters:
	alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
	*/
	match, _ := regexp.MatchString(`^([[:alnum:]]|[_\-\.@])*$`, name)
	return match
}

// Check that path is not group or other writable
func checkNotWritable(path string) bool {
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

// remove all empty strings from string slice
func removeEmptyStrings(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

// remove all comments from string slice
func removeComments(s []string) []string {
	var r []string
	reg, _ := regexp.Compile(`^[[:blank:]]*#`)
	for _, str := range s {
		if match := reg.MatchString(`^[[:blank:]]*#`); !match {
			r = append(r, str)
		}
	}
	return r
}

func setLogFormatter(debug bool, username string) {
	luuid := uuid.NewString()
	var format string
	if username == "" {
		format = fmt.Sprintf("%%time%% [okta-auth-validator:%s](%%lvl%%): %%msg%%\n", luuid)
	} else {
		format = fmt.Sprintf(
			"%%time%% [okta-auth-validator:%s](%%lvl%%): [%s] %%msg%%\n",
			luuid,
			username)
	}
	log.SetFormatter(&easy.Formatter{
		TimestampFormat: time.ANSIC,
		LogFormat:       format,
	})
	if debug {
		log.SetLevel(log.DebugLevel)
	}
}
