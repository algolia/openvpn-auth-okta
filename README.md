![Release](https://img.shields.io/github/v/release/algolia/openvpn-auth-okta.svg)
![Go version](https://img.shields.io/github/go-mod/go-version/algolia/openvpn-auth-okta.svg)
[![Go Reference](https://pkg.go.dev/badge/gopkg.in/algolia/openvpn-auth-okta.v2.svg)](https://pkg.go.dev/gopkg.in/algolia/openvpn-auth-okta.v2)
![CI status](https://circleci.com/gh/algolia/openvpn-auth-okta/tree/v2.svg?style=shield)
![Coverage](https://img.shields.io/badge/Coverage-97.5%25-brightgreen)
[![Go Report Card](https://goreportcard.com/badge/gopkg.in/algolia/openvpn-auth-okta.v2)](https://goreportcard.com/report/gopkg.in/algolia/openvpn-auth-okta.v2)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/66b5143777dc441993ebfcea172e0626)](https://app.codacy.com/gh/algolia/openvpn-auth-okta/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

# Introduction

This offers a set of lib and binary to authenticate users against [Okta Authentication API](https://developer.okta.com/docs/reference/api/authn/) , with support for MFA (TOTP or PUSH only).
It also offers a plugin for OpenVPN (Community Edition) using the lib mentionned above.

> :exclamation: Note: The plugin does not work with OpenVPN Access Server (OpenVPN-AS)

# Requirements

The plugin requires that OpenVPN Community Edition to be configured or used in one the following ways:

1. OpenVPN can be configured to call plugins via a deferred call (aka `Shared Object Plugin` mode) or call the binary directly (aka `Script Plugin` mode).
2. By default, OpenVPN clients *must* authenticate using client SSL certificates.
3. If authenticating requires MFA, the end user will authenticate by appending their six-digit MFA TOTP to the end of its password or by validating Push notifications.

For TOTP, if a user's password is `correcthorsebatterystaple` and their six-digit MFA TOTP is `123456`, he should use `correcthorsebatterystaple123456` as the password for their OpenVPN client

# Installation

## Install the Okta OpenVPN plugin

You have three options to install the Okta OpenVPN plugin:

### 1.  Use pre-built packages from repositories

Thanks to the [OpenSUSE Build Service](https://build.opensuse.org/) packages are available for multiple distros: CentOS, Debian, Fedora, openSUSE, Ubuntu.

Choose the proper instructions for your Linux distribution [here](https://software.opensuse.org/download/package?package=openvpn-auth-okta&project=home%3AAlgolia%3AOSS).

#### Packages are available for

- CentOS (amd64, arm64): `8`, `8 Stream`
- Fedora (amd64, arm64): `38`, `39`, `40`
- Mageia (amd64, arm64): `8`, `9`
- openSUSE (amd64, arm64, ppc64le): `15.4`, `15.5`, `15.5`
- Debian (amd64, arm64): `Buster` (10), `Bullseye` (11), `Bookworm` (12)
- Raspbian(arm64): `10`, `11`, `12`
- Ubuntu (amd64, arm64): `Focal Fossa` (20.04), `Jammy Jellyfish` (22.04), `Lunar Lobster` (23.04), `Mantic Minotaur` (23.10), `Noble Numbat` (24.04)

### 2.  For default setups, use `sudo make install` to run the install for you

Build requirements:

- gcc
- golang (>= 1.21)
- make

If you have a default OpenVPN setup, where plugins are stored in `/usr/lib/openvpn/plugins` and configuration files are stored in `/etc/okta-auth-validator`, then you can use the `make install` command to install the Okta OpenVPN plugin:

```shell
sudo make install
```

### 3.  For custom setups, follow the manual installation instructions below

#### Compile the plugin

Build requirements:

- gcc
- golang (>= 1.21)
- make

Compile the plugin from this directory using this command:

```shell
make plugin
```

Compile the Golang binary from this repository using this command:

```shell
make binary
```

#### Manually installing the Okta OpenVPN plugin

If you have a custom setup, follow the instructions below to install the C plugin and Golang library that constitute the Okta OpenVPN plugin.

#### Manually installing the C Plugin

To manually install the C plugin, copy the `build/openvpn-plugin-auth-okta.so` file to the location where your OpenVPN plugins are stored and the `libokta-auth-validator.so` file to your system libdir.

#### Manually installing the Golang binary

To manually install the binary, copy the `okta-auth-validator` to your system bin dir; the `pinset.cfg`, and `api.ini` files to the location where your OpenVPN plugin scripts are stored.

## Make sure that OpenVPN has a tempory directory

In OpenVPN, the "deferred plugin" model requires the use of temporary files to work. It is recommended that these temporary files are stored in a directory that only OpenVPN has access to. The default location for this directory is `/etc/openvpn/tmp`. If this directory doesn't exist, create it using this command:

```shell
sudo mkdir /etc/openvpn/tmp
```

Use the [chown](https://en.wikipedia.org/wiki/Chown) and [chmod](https://en.wikipedia.org/wiki/Chmod) commands to set permissions approprate to your setup (The user that runs OpenVPN should be owner and only writer).

# Configuration

## Configure the Okta OpenVPN plugin

The Okta OpenVPN plugin is configured using the `api.ini` file. You **must** update this file with the configuration options for your Okta organization for the plugin to work.

If you installed the Okta OpenVPN plugin to the default location, run this command to edit your configuration file.

```shell
sudo $EDITOR /etc/okta-auth-validator/api.ini
```
> :warning: As this file contains your Okta token, please ensure it has limited permissions (should only be readable by root or the user running OpenVPN) !

See [api.ini](https://github.com/algolia/openvpn-auth-okta/blob/v2/api.ini.inc) for configuration options.

## Configure OpenVPN to use the C `Shared Object Plugin`

Set up OpenVPN to call the Okta plugin by adding the following lines to your OpenVPN `server.conf` configuration file:

```ini
plugin openvpn-plugin-auth-okta.so
tmp-dir "/etc/openvpn/tmp"
```

The default location for the OpenVPN configuration file is `/etc/openvpn/server.conf`.  
This method is considered the safest as no credential is exported to a process environment or written to disk.

## Configure OpenVPN to use the binary in `Script Plugin` mode

Set up OpenVPN to call the Golang binary by adding the following lines to your OpenVPN `server.conf` configuration file:

```ini
# "via-file" method
auth-user-pass-verify /usr/bin/okta-auth-validator via-file
tmp-dir "/etc/openvpn/tmp"
```
> :exclamation: it is strongly advised when using the via file method, that the tmp-dir is located on a tmpfs filesystem (so that the user's credentials never reach the disk). Systemd can help for that:

```shell
VUSER=openvpn
echo "d /run/openvpn/tmp 1750 ${VUSER} root" | sudo tee /etc/tmpfiles.d/openvpn-tmp.conf
sudo systemd-tmpfiles  --create /etc/tmpfiles.d/openvpn-tmp.conf
```

```ini
# "via-env" method
auth-user-pass-verify /usr/bin/okta-auth-validator via-env
tmp-dir "/etc/openvpn/tmp"
```

Please check the OpenVPN [manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-0/#options) for security considerations regarding this mode.

# Log outputs

Outputs have been designed to be easily parsable, you'll find 2 different formats depending on wether the username has been set or not, ie:

Before
```
Thu Dec 21 03:41:28 2023 [okta-auth-validator:4dd5f892-c51d-43bf-94c7-87b25b81707e](ERROR): Initpool failure
```

After
```
Thu Dec 21 03:41:28 2023 [okta-auth-validator:50bc833a-dcea-4337-9d73-41af17371c4e](INFO): [dade.murphy@example.com] Authenticating
```

A grok pattern could be:
```
DATESTAMP_OKTA %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}
%{DATESTAMP_OKTA:timestamp} \[okta-auth-validator:%{UUID:session_id}\]\(%{LOGLEVEL:level}\):(%{SPACE}\[((%{EMAILADDRESS:username})|(%{EMAILLOCALPART:username}))\])? %{GREEDYDATA:message}
```

# Useful links

- [OpenVPN: Using alternative authentication methods](https://openvpn.net/community-resources/using-alternative-authentication-methods/)
- [OpenVPN 2.4 manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
- [Openvpn multi-auth sample plugin code](https://github.com/OpenVPN/openvpn/blob/master/sample/sample-plugins/defer/multi-auth.c)
- [Okta API - PreAuth](https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application)
- [Okta API - Auth with TOTP MFA](https://developer.okta.com/docs/reference/api/authn/#verify-totp-factor)
- [Okta API - Auth with Push MFA](https://developer.okta.com/docs/reference/api/authn/#verify-push-factor)

# Contact

Updates or corrections to this document are very welcome. Feel free to send me [pull requests](https://help.github.com/articles/using-pull-requests/) with suggestions or open issues.
