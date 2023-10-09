[OktaAPI]
## The URL for your Okta instance
## (Example below)
# Url: https://example.okta.com
Url: 

## The API Token for your Okta instace
## (Example below)
# Token: 01Abcd2efGHIjKl3m4NoPQrstu5vwxYZ_AbcdefGHi
Token: 

## An OPTIONAL suffix to be appended to the end of user names
## before the attempting authentication against Okta.
##   For example: If this was set to 'example.com', a user with a
##   certificate identifiying them as 'first.last' would be authenticated
##   against Okta as 'first.last@example.com'.
## (Example below)
# UsernameSuffix: example.com

## Do not require usernames to come from client-side SSL certificates.
## NOT RECCOMMENDED FOR PRODUCTION ENVIRONMENTS
## (Example below)
# AllowUntrustedUsers: True

# Always request MFA validation (TOTP or PUSH)
# If PreAuth is successful without MFA challenge, user will be rejected
## (Example below)
# MFARequired: True

## Configure how often poll Okta for results of an Okta Verify Push
## Values below are what are set by default:
# MFAPushMaxRetries: 20
# MFAPushDelaySeconds: 3
