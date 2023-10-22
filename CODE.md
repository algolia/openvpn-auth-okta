- [An overview of how openvpn-auth-okta works](#overview)
  - [Instantiate an OktaOpenVPNValidator struct](#instantiate)
  - [Load in configuration file and environment variables](#setup)
  - [Authenticate the user](#authenticate)
  - [Write result to the control file (`Shared Object Plugin` mode)](#write_to_control_file)
- [Learn more](#more)


<a id="overview"></a>

# An overview of how openvpn-auth-okta works

This is a plugin for OpenVPN Community Edition that allows OpenVPN to authenticate directly against Okta, with support for TOTP and Okta Verify Push factors.

At a high level, when configured in `Shared Object Plugin` mode, OpenVPN communicates with this plugin via a "control file", a temporary file that OpenVPN creates and polls periodicly. If the plugin writes the ASCII character "1" into the control file, the user in question is allowed to log in to OpenVPN, if we write the ASCII character "0" into the file, the user is denied. Exit code is expected to always be 0.

In `Script Plugin` mode, OpenVPN expects the exit code of the binary to be 0 if the user is allowed, 1 otherwise. OpenVPN trnasfers the user informations to the binary using:
- a local file when configured with `via-file` method
- environment variables when configured with `via-env` method

Below are the key parts of the code for `okta-auth-validator` binary:

1.  Instantiate an OktaOpenVPNValidator struct
2.  Load in configuration file and (environment variables or via-file)
3.  Authenticate the user
4.  Write result to the control file or exit with code reflecting user allowance


<a id="instantiate"></a>

## Instantiate an OktaOpenVPNValidator struct

The code flow for authenticating a user is as follows:

Here is how we instantiate an OktaOpenVPNValidator struct:

```go
func main() {
    validator := validator.NewOktaOpenVPNValidator()
```


<a id="setup"></a>

## Load in configuration file and environment variables

Here is the `Setup(...)` method of the OktaOpenVPNValidator package, this is what calls the methods which load the configuration file and environment variables.

```go
func (validator *OktaOpenVPNValidator) Setup(deferred bool, args []string) {
  if err := validator.ReadConfigFile(); err != nil {
    if deferred {
      validator.SetControlFile(os.Getenv("auth_control_file"))
      validator.WriteControlFile()
    }
    return false
  }

  if !deferred {
    // We're running in "Script Plugins" mode with "via-env" method
    if len(args) > 0 {
      // via-file" method
      if err := validator.LoadViaFile(args[0]); err != nil {
        return false
      }
    } else {
      // "via-env" method
      if err := validator.LoadEnvVars(nil); err != nil {
        return false
      }
    }
  } else {
    // We're running in "Shared Object Plugin" mode
    if err := validator.LoadEnvVars(pluginEnv); err != nil {
      validator.WriteControlFile()
      return false
    }
  }

  if err := validator.LoadPinset(); err != nil {
    if deferred {
      validator.WriteControlFile()
    }
    return false
  }
  validator.parsePassword()
  if err := validator.api.InitPool(); err != nil {
    return false
  }
  return true
}
```


<a id="authenticate"></a>

## Authenticate the user

Here is the `Authenticate()` method:

```go
func (validator *OktaOpenVPNValidator) Authenticate() {
  if !validator.usernameTrusted {
    fmt.Printf("[%s] User is not trusted - failing\n", validator.api.UserConfig.Username)
    return errors.New("User not trusted")
  }
  if err := validator.api.Auth(); err == nil {
    validator.isUserValid = true
    return nil
  } else {
    return errors.New("Authentication failed")
  }
}
```

This code in turns calls the `Auth()` method in the `OktaAPIAuth` struct, which does the following:

-   Makes an authentication request to Okta, using the `preAuth()` method.
-   Checks for errors
-   Log the user in if the reply was `SUCCESS`
-   Deny the user if the reply is `LOCKED_OUT`, `MFA_ENROLL` or `MFA_ENROLL_ACTIVATE`

If the response is `MFA_REQUIRED` or `MFA_CHALLENGE` then we do the following, for each factor that the user has registered:

-   Skip the factor if this code doesn't support that factor type.
-   Call `doAuth()`, the second phase authentication, using the passcode (if we have one) and the `stateToken`.
    -   Keep running `doAuth()` if the response type is or `WAITING`.
-   If there response from `doAuth()` is `SUCCESS` then log the user in.
-   Fail otherwise.

When returning errors, we prefer the summary strings in `errorCauses`, over those in `errorSummary` because the strings in `errorCauses` tend to be mroe descriptive. For more information, see the documentation for [Verify Security Question Factor](http://developer.okta.com/docs/api/resources/authn.html#verify-security-question-factor).


<a id="write_to_control_file"></a>

## Write result to the control file (`Shared Object Plugin` mode)

**Important:** The key thing to know about OpenVPN plugins (like this one) are that they communicate with OpenVPN through a **control file**. When OpenVPN calls a plugin, it first creates a temporary file, passes the name of the temporary file to the plugin, then waits for the temporary file to be written.

If a "**1**" is written to the file, OpenVPN logs the user in. If a "**0**" is written to the file, the user is denied.

Here is what the code does below:

Because of how critical this control file is, we take the precaution of checking the permissions on the control file before writing anything to the file.

If the user authentication that happened previously was a success, we write a **1** to the file. Otherwise, we write a **0** to the file, denying the user by default.

```go
func (validator *OktaOpenVPNValidator) WriteControlFile() {
  if err := validator.checkControlFilePerm(); err != nil {
    return
  }

  valToWrite := []byte("0")
  if validator.isUserValid {
    valToWrite = []byte("1")
  }
  if err := os.WriteFile(validator.controlFile, valToWrite, 0600); err !=nil {
    fmt.Printf("Failed to write to OpenVPN control file %s\n", validator.controlFile)
  }
}
```


<a id="more"></a>

# Learn more

Read the source on GitHub: <https://github.com/algolia/openvpn-auth-okta>
See the [Useful links](https://github.com/algolia/openvpn-auth-okta#useful-links) in the [README](https://github.com/algolia/openvpn-auth-okta#readme).
