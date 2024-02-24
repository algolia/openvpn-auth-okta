[General]
## Set the out log level
## Allowed values: TRACE, DEBUG, INFO, WARN, ERROR
## (Optional, default: INFO)
LogLevel: INFO

[OktaAPI]
## The URL for your Okta instance
## (Required)
# Url: https://example.okta.com
Url: 

## The API Token for your Okta instace
## (Required)
# Token: 01Abcd2efGHIjKl3m4NoPQrstu5vwxYZ_AbcdefGHi
Token: 

## A suffix to be appended to the end of user names
## before the attempting authentication against Okta.
##   For example: If this was set to 'example.com', a user with a
##   certificate / username identifiying them as 'first.last' would be authenticated
##   against Okta as 'first.last@example.com'.
## (Optional, default: "")
# UsernameSuffix: example.com

## Do not require usernames to come from client-side SSL certificates.
## NOT RECCOMMENDED FOR PRODUCTION ENVIRONMENTS
## (Optional, default: False)
# AllowUntrustedUsers: True

## Configure what groups are allowed to connect to server (comma separated list)
## (Optional, default: "")
# AllowedGroups: vpnusers, developers

## Always request MFA validation (TOTP or PUSH)
## If PreAuth is successful without MFA challenge, user will be rejected
## (Optional, default: False)
# MFARequired: True

## Configure how many retries to poll Okta for results of an Okta Verify Push are allowed
## (Optional, default: 20)
# MFAPushMaxRetries: 20

## Configure how many seconds to wait between Okta Verify Push retries
## (Optional, default: 3)
# MFAPushDelaySeconds: 3

# If a passcode is provided and TOTP MFA fails, try Push MFA
## (Optional, default: False)
TOTPFallbackToPush: False
