![Release](https://img.shields.io/github/v/release/algolia/openvpn-auth-okta.svg)
![Go version](https://img.shields.io/github/go-mod/go-version/algolia/openvpn-auth-okta.svg)
[![Go Reference](https://pkg.go.dev/badge/gopkg.in/algolia/openvpn-auth-okta.v2.svg)](https://pkg.go.dev/gopkg.in/algolia/openvpn-auth-okta.v2)
![CI status](https://circleci.com/gh/algolia/openvpn-auth-okta/tree/v2.svg?style=shield)
![Coverage](https://img.shields.io/badge/Coverage-94.1%25-brightgreen)
[![Go Report Card](https://goreportcard.com/badge/gopkg.in/algolia/openvpn-auth-okta.v2)](https://goreportcard.com/report/gopkg.in/algolia/openvpn-auth-okta.v2)

# Introduction

This is a plugin/binary for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA (TOTP or PUSH only).

> :exclamation: Note: This plugin does not work with OpenVPN Access Server (OpenVPN-AS)


# Requirements

This plugin requires that OpenVPN Community Edition be configured or used in one the following ways:

1.  OpenVPN can be configured to call plugins via a deferred call (aka `Shared Object Plugin` mode) or call the binary directly (aka `Script Plugin` mode).
2.  By default, OpenVPN clients *must* authenticate using client SSL certificates.
3.  If authenticating requires MFA, the end user will authenticate by appending their six-digit MFA TOTP to the end of their password or by validating Push notifications.

For TOTP, if a user's password is `correcthorsebatterystaple` and their six-digit MFA TOTP is `123456`, they would use `correcthorsebatterystaple123456` as the password for their OpenVPN client


# Installation


## Compile the C plugin

Build requirements:
  - gcc
  - golang (>= 1.21)
  - make

Compile the C plugin from this directory using this command:

```shell
$ make plugin
```

Compile the Golang binary plugin from this directory using this command:

```shell
$ make binary
```


## Install the Okta OpenVPN plugin

You have three options to install the Okta OpenVPN plugin:

### 1.  For default setups, use `sudo make install` to run the install for you.

If you have a default OpenVPN setup, where plugins are stored in `/usr/lib/openvpn/plugins` and configuration files are stored in `/etc/okta-auth-validator`, then you can use the `make install` command to install the Okta OpenVPN plugin:

```shell
$ sudo make install
```

### 2.  Use pre-built packages from repositories

Thanks to the [OpenSUSE Build Service](https://build.opensuse.org/) packages are available for multiple distros: CentOS, Debian, Fedora, openSUSE, Ubuntu.

##### Debian, Ubuntu:
```shell
# supports Debian 11, 12 and Ubuntu 20.04, 22.04, 23.04, 23.10
. /etc/os-release
if [ "${NAME}" = "Ubuntu" ]
then
  DIST="xUbuntu"
else
  DIST="Debian"
fi

echo "deb [arch=amd64 trusted=yes] \"https://download.opensuse.org/repositories/home:/Algolia:/OSS/${DIST}_${VERSION_ID}\" ./" | sudo tee /etc/apt/sources.list.d/algolia-oss.list

wget https://download.opensuse.org/repositories/home:/Algolia:/OSS/${DIST}_${VERSION_ID}/Release.key -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install openvpn-auth-okta
```

##### openSUSE

```shell
# supports openSUSE 15.4, 15.5
. /etc/os-release

wget -q  https://download.opensuse.org/repositories/home:/Algolia:/OSS/${VERSION_ID}/home:Algolia:OSS.repo -O- | sudo tee /etc/zypp/repos.d/algolia-oss.repo

sudo zypper ref
sudo zypper install openvpn-auth-okta
```

##### CentOS

```shell
# supports CentOS 8, 8-stream, 9
. /etc/os-release

wget -q  https://download.opensuse.org/repositories/home:/Algolia:/OSS/CentOS_${VERSION_ID}/home:Algolia:OSS.repo -O- | sudo tee /etc/yum.repos.d/algolia-oss.repo

sudo yum install -y openvpn-auth-okta
```

##### Fedora

```shell
# supports Fedora 38, 39
. /etc/os-release

wget -q  https://download.opensuse.org/repositories/home:/Algolia:/OSS/Fedora_${VERSION_ID}/home:Algolia:OSS.repo -O- | sudo tee /etc/yum.repos.d/algolia-oss.repo

sudo yum install -y openvpn-auth-okta
```


### 3.  For custom setups, follow the manual installation instructions below.

#### Manually installing the Okta OpenVPN plugin

If you have a custom setup, follow the instructions below to install the C plugin and Golang binary that constitute the Okta OpenVPN plugin.


#### Manually installing the C Plugin

To manually install the C plugin, copy the `build/openvpn-plugin-auth-okta.so` file to the location where your OpenVPN plugins are stored and the `libokta-auth-validator.so`file to your system libdir.


#### Manually installing the Golang binary

To manually install the binary, copy the `okta-auth-validator` to your system bin dir; the `pinset.cfg`, and `api.ini` files to the location where your OpenVPN plugin scripts are stored.


## Make sure that OpenVPN has a tempory directory

In OpenVPN, the "deferred plugin" model requires the use of temporary files to work. It is recommended that these temporary files be stored in a directory that only OpenVPN has access to. The default location for this directory is `/etc/openvpn/tmp`. If this directory doesn't exist, create it using this command:

```shell
$ sudo mkdir /etc/openvpn/tmp
```

Use the [chown](https://en.wikipedia.org/wiki/Chown) and [chmod](https://en.wikipedia.org/wiki/Chmod) commands to set permissions approprate to your setup (The user that runs OpenVPN should be owner and only writer).


# Configuration

## Configure the Okta OpenVPN plugin

The Okta OpenVPN plugin is configured via the `api.ini` file. You **must** update this file with the configuration options for your Okta organization for the plugin to work.

If you installed the Okta OpenVPN plugin to the default location, run this command to edit your configuration file.

```shell
$ sudo $EDITOR /etc/okta-auth-validator/api.ini
```
> :warning: As this file contains your Okta token, please ensure it has limited permissions (should only be readable by root or the user running OpenVPN) !

See [api.ini](https://github.com/algolia/openvpn-auth-okta/blob/v2/api.ini.inc) for configuration options.


## Configure OpenVPN to use the C `Shared Object Plugin`

Set up OpenVPN to call the Okta plugin by adding the following lines to your OpenVPN `server.conf` configuration file:

```ini
plugin openvpn-plugin-auth-okta.so
tmp-dir "/etc/openvpn/tmp"
```

The default location for OpenVPN configuration files is `/etc/openvpn/server.conf`.  
This method is considered the safest as no credential is exported to a process environment or written to disk.


## Configure OpenVPN to use the binary in `Script Plugin` mode

Set up OpenVPN to call the Okta Golang binary by adding the following lines to your OpenVPN `server.conf` configuration file:

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

The default location for OpenVPN configuration files is usually `/etc/openvpn/server.conf`


# Useful links

- [OpenVPN: Using alternative authentication methods](https://openvpn.net/community-resources/using-alternative-authentication-methods/)
- [OpenVPN 2.4 manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/)
- [Openvpn multi-auth sample plugin code](https://github.com/OpenVPN/openvpn/blob/master/sample/sample-plugins/defer/multi-auth.c)
- [Okta API - PreAuth](https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application)
- [Okta API - Auth with TOTP MFA](https://developer.okta.com/docs/reference/api/authn/#verify-totp-factor)
- [Okta API - Auth with Push MFA](https://developer.okta.com/docs/reference/api/authn/#verify-push-factor)


# Contact

Updates or corrections to this document are very welcome. Feel free to send me [pull requests](https://help.github.com/articles/using-pull-requests/) with suggestions.
