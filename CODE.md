- [An overview of how okta-openvpn works](#org835b848)
  - [Instantiate an OktaOpenVPNValidator object](#org3ac730b)
  - [Load in configuration file and environment variables](#org5d7701b)
  - [Authenticate the user](#org3312102)
  - [Write result to the control file](#orgab0ed37)
- [Learn more](#org9c0edcb)


<a id="org835b848"></a>

# An overview of how okta-openvpn works

This is a plugin for OpenVPN Community Edition that allows OpenVPN to authenticate directly against Okta, with support for TOTP and Okta Verify Push factors.

At a high level, OpenVPN communicates with this plugin via a "control file", a temporary file that OpenVPN creates and polls periodicly. If the plugin writes the ASCII character "1" into the control file, the user in question is allowed to log in to OpenVPN, if we write the ASCII character "0" into the file, the user is denied.

Below are the key parts of the code for `okta_openvpn.py`:

1.  Instantiate an OktaOpenVPNValidator object
2.  Load in configuration file and environment variables
3.  Authenticate the user
4.  Write result to the control file


<a id="org3ac730b"></a>

## Instantiate an OktaOpenVPNValidator object

The code flow for authenticating a user is as follows:

Here is how we instantiate an OktaOpenVPNValidator object:

```python
# This is tested by test_command.sh via tests/test_command.py
if __name__ == "__main__":  # pragma: no cover
    validator = OktaOpenVPNValidator()
    validator.run()
    return_error_code_for(validator)
```


<a id="org5d7701b"></a>

## Load in configuration file and environment variables

Here is the `run()` method of the OktaOpenVPNValidator class, this is what calls the methods which load the configuration file and environment variables, then calls the `authenticate()` method.

```python
def run(self):
    self.read_configuration_file()
    self.load_environment_variables()
    self.authenticate()
    self.write_result_to_control_file()
```


<a id="org3312102"></a>

## Authenticate the user

Here is the `authenticate()` method:

```python
def authenticate(self):
    if not self.username_trusted:
        log.warning("Username %s is not trusted - failing",
                    self.okta_config['username'])
        return False
    try:
        okta = self.cls(**self.okta_config)
        self.user_valid = okta.auth()
        return self.user_valid
    except Exception as exception:
        log.error(
            "User %s (%s) authentication failed, "
            "because %s() failed unexpectedly - %s",
            self.okta_config['username'],
            self.okta_config['client_ipaddr'],
            self.cls.__name__,
            exception
        )
    return False
```

This code in turns calls the `auth()` method in the `OktaAPIAuth` class, which does the following:

-   Makes an authentication request to Okta, using the `preauth()` method.
-   Checks for errors
-   Log the user in if the reply was `SUCCESS`
-   Deny the user if the reply is `MFA_ENROLL` or `MFA_ENROLL_ACTIVATE`

If the response is `MFA_REQUIRED` or `MFA_CHALLENGE` then we do the following, for each factor that the user has registered:

-   Skip the factor if this code doesn't support that factor type.
-   Call `doauth()`, the second phase authentication, using the passcode (if we have one) and the `stateToken`.
    -   Keep running `doauth()` if the response type is `MFA_CHALLENGE` or `WAITING`.
-   If there response from `doauth()` is `SUCCESS` then log the user in.
-   Fail otherwise.

When returning errors, we prefer the summary strings in `errorCauses`, over those in `errorSummary` because the strings in `errorCauses` tend to be mroe descriptive. For more information, see the documentation for [Verify Security Question Factor](http://developer.okta.com/docs/api/resources/authn.html#verify-security-question-factor).

```python
try:
    rv = self.preauth()
except Exception as s:
    log.error('Error connecting to the Okta API: %s', s)
    return False
# Check for erros from Okta
if 'errorCauses' in rv:
    msg = rv['errorSummary']
    log.info('User %s pre-authentication failed: %s',
             self.username,
             msg)
    return False
elif 'status' in rv:
    status = rv['status']
# Check authentication status from Okta
if status == "SUCCESS":
    log.info('User %s authenticated without MFA', self.username)
    return True
elif status == "MFA_ENROLL" or status == "MFA_ENROLL_ACTIVATE":
    log.info('User %s needs to enroll first', self.username)
    return False
elif status == "MFA_REQUIRED" or status == "MFA_CHALLENGE":
    log.debug("User %s password validates, checking second factor",
              self.username)
    res = None
    for factor in rv['_embedded']['factors']:
        supported_factor_types = ["token:software:totp", "push"]
        if factor['factorType'] not in supported_factor_types:
            continue
        fid = factor['id']
        state_token = rv['stateToken']
        try:
            res = self.doauth(fid, state_token)
            check_count = 0
            fctr_rslt = 'factorResult'
            while fctr_rslt in res and res[fctr_rslt] == 'WAITING':
                print("Sleeping for {}".format(
                    self.mfa_push_delay_secs))
                time.sleep(self.mfa_push_delay_secs)
                res = self.doauth(fid, state_token)
                check_count += 1
                if check_count > self.mfa_push_max_retries:
                    log.info('User %s MFA push timed out' %
                             self.username)
                    return False
        except Exception as e:
            log.error('Unexpected error with the Okta API: %s', e)
            return False
        if 'status' in res and res['status'] == 'SUCCESS':
            log.info("User %s is now authenticated "
                     "with MFA via Okta API", self.username)
            return True
    if 'errorCauses' in res:
        msg = res['errorCauses'][0]['errorSummary']
        log.debug('User %s MFA token authentication failed: %s',
                  self.username,
                  msg)
    return False
else:
    log.info("User %s is not allowed to authenticate: %s",
             self.username,
             status)
    return False
```


<a id="orgab0ed37"></a>

## Write result to the control file

**Important:** The key thing to know about OpenVPN plugins (like this one) are that they communicate with OpenVPN through a **control file**. When OpenVPN calls a plugin, it first creates a temporary file, passes the name of the temporary file to the plugin, then waits for the temporary file to be written.

If a "**1**" is written to the file, OpenVPN logs the user in. If a "**0**" is written to the file, the user is denied.

Here is what the code does below:

Because of how critical this control file is, we take the precaution of checking the permissions on the control file before writing anything to the file.

If the user authentication that happened previously was a success, we write a **1** to the file. Otherwise, we write a **0** to the file, denying the user by default.

```python
def write_result_to_control_file(self):
    self.check_control_file_permissions()
    try:
        with open(self.control_file, 'w') as f:
            if self.user_valid:
                f.write('1')
            else:
                f.write('0')
    except IOError:
        log.critical("Failed to write to OpenVPN control file '{}'".format(
            self.control_file
        ))
```


<a id="org9c0edcb"></a>

# Learn more

Read the source on GitHub: <https://github.com/okta/okta-openvpn>

Key files to read:

-   <https://github.com/okta/okta-openvpn/blob/master/tests/test_OktaOpenVPNValidator.py>
-   <https://github.com/okta/okta-openvpn/blob/master/okta_openvpn.py>
