![Coverage](https://img.shields.io/badge/Coverage-90.9%25-brightgreen)
![Go version](https://img.shields.io/github/go-mod/go-version/algolia/okta-openvpn.svg)
![CI status](https://circleci.com/gh/algolia/okta-openvpn/tree/v2.svg?style=shield)

# Introduction

This is a plugin/binary for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA (TOTP or PUSH only).

    Note: This plugin does not work with OpenVPN Access Server (OpenVPN-AS)


# Requirements

This plugin requires that OpenVPN Community Edition be configured or used in one the following ways:

1.  OpenVPN can be configured to call plugins via a deferred call (aka `Shared Object Plugin` mode) or call the binary directly (aka `Script Plugin` mode).
2.  By default, OpenVPN clients *must* authenticate using client SSL certificates.
3.  If authenticating using MFA, the end user will authenticate by appending their six-digit MFA TOTP to the end of their password or by validating Push notifications.

For TOTP, if a user's password is `correcthorsebatterystaple` and their six-digit MFA TOTP is `123456`, they would use `correcthorsebatterystaple123456` as the password for their OpenVPN client


# Installation

## Compile the C plugin

Compile the C plugin from this directory using this command:

```shell
$ make plugin
```

Compile the Golang binary plugin from this directory using this command:

```shell
$ make script
```


## Install the Okta OpenVPN plugin

You have two options to install the Okta OpenVPN plugin:

1.  For default setups, use `make install` to run the install for you.
2.  For custom setups, follow the manual installation instructions below.

If you have a default OpenVPN setup, where plugins are stored in `/usr/lib/openvpn/plugins` and configuration files are stored in `/etc/openvpn`, then you can use the `make install` command to install the Okta OpenVPN plugin:

```shell
$ sudo make install
```


## Manually installing the Okta OpenVPN plugin

If you have a custom setup, follow the instructions below to install the C plugin and Golang binary that constitute the Okta OpenVPN plugin.


### Manually installing the C Plugin

To manually install the C plugin, copy the `defer\_simple.so` file to the location where your OpenVPN plugins are stored.


### Manually installing the Golang binary

To manually install the binary, copy the `okta\_openvpn`, `okta\_pinset.cfg`, and `okta\_openvpn.ini` files to the location where your OpenVPN plugin scripts are stored.


## Make sure that OpenVPN has a tempory directory

In OpenVPN, the "deferred plugin" model requires the use of temporary files to work. It is recommended that these temporary files be stored in a directory that only OpenVPN has access to. The default location for this directory is `/etc/openvpn/tmp`. If this directory doesn't exist, create it using this command:

```shell
$ sudo mkdir /etc/openvpn/tmp
```

Use the [chown](https://en.wikipedia.org/wiki/Chown) and [chmod](https://en.wikipedia.org/wiki/Chmod) commands to set permissions approprate to your setup (The user that runs OpenVPN should be owner and only writer).


# Configuration

## Configure the Okta OpenVPN plugin

The Okta OpenVPN plugin is configured via the `okta\_openvpn.ini` file. You **must** update this file with the configuration options for your Okta organization for the plugin to work.

If you installed the Okta OpenVPN plugin to the default location, run this command to edit your configuration file.

```shell
$ sudo $EDITOR /etc/openvpn/okta_openvpn.ini
```


## Configure OpenVPN to use the C Shared Plugin

Set up OpenVPN to call the Okta plugin by adding the following lines to your OpenVPN `server.conf` configuration file:

```ini
plugin /usr/lib/openvpn/plugins/defer_simple.so /usr/lib/openvpn/plugins/okta_openvpn
tmp-dir "/etc/openvpn/tmp"
```

The default location for OpenVPN configuration files is `/etc/openvpn/server.conf`


## Configure OpenVPN to use the binary in `Script Plugin` mode

Set up OpenVPN to call the Okta Golang binary by adding the following lines to your OpenVPN `server.conf` configuration file:

```ini
# "via-file" method
auth-user-pass-verify /usr/lib/openvpn/plugins/okta_openvpn via-file
tmp-dir "/etc/openvpn/tmp"
```

```ini
# "via-env" method
auth-user-pass-verify /usr/lib/openvpn/plugins/okta_openvpn via-env
tmp-dir "/etc/openvpn/tmp"
```

Please check the OpenVPN [manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-0/#options) for security considerations regarding this mode.

The default location for OpenVPN configuration files is `/etc/openvpn/server.conf`


# Useful links

- [OpenVPN: Using alternative authentication methods](https://openvpn.net/community-resources/using-alternative-authentication-methods/)
- [OpenVPN 2.4 manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
- [Openvpn auth-pam plugin code](https://github.com/OpenVPN/openvpn/tree/master/src/plugins/auth-pam)
- [Okta API - PreAuth](https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application)
- [Okta API - Auth with TOTP MFA](https://developer.okta.com/docs/reference/api/authn/#verify-totp-factor)
- [Okta API - Auth with Push MFA](https://developer.okta.com/docs/reference/api/authn/#verify-push-factor)


# Contact

Updates or corrections to this document are very welcome. Feel free to send me [pull requests](https://help.github.com/articles/using-pull-requests/) with suggestions.
