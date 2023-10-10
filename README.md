# Introduction

This is a plugin for OpenVPN (Community Edition) that authenticates users directly against Okta, with support for MFA.

    Note: This plugin does not work with OpenVPN Access Server (OpenVPN-AS)


# Requirements

This plugin requires that OpenVPN Community Edition be configured or used in the following ways:

1.  OpenVPN must be configured to call plugins via a deferred call.
2.  By default, OpenVPN clients *must* authenticate using client SSL certificates.
3.  If authenticating using MFA, the end user will authenticate by appending their six-digit MFA token to the end of their password.

For example, if a user's password is `correcthorsebatterystaple` and their six-digit MFA token is `123456`, they would use `correcthorsebatterystaple123456` as the password for their OpenVPN client


# Setup and Configuration


## Verify the GPG signature on this repository

The source code for this plugin is signed using [GPG](https://gnupg.org/).

It is recommended that this plugin be verified using the <code>git tag -v $TAGNAME</code> command.

For example, to verify the v0.10.0 tag, use the command below:

```shell
$ git tag -v v2.1.4
```


## Compile the C plugin

Compile the C plugin from this directory using this command:

```shell
$ make plugin
```

Compile the Golang binary plugin from this directory using this command:

```shell
$ make plugin
```


## Install the Okta OpenVPN plugin

You have two options to install the Okta OpenVPN plugin:

1.  For default setups, use <code>make install</code> to run the install for you.
2.  For custom setups, follow the manual installation instructions below.

If you have a default OpenVPN setup, where plugins are stored in <code>/usr/lib/openvpn/plugins</code> and configuration files are stored in <code>/etc/openvpn</code>, then you can use the <code>make install</code> command to install the Okta OpenVPN plugin:

```shell
$ sudo make install
```


## Manually installing the Okta OpenVPN plugin

If you have a custom setup, follow the instructions below to install the C plugin and Python scripts that constitute the Okta OpenVPN plugin.


### Manually installing the C Plugin

To manually install the C plugin, copy the <code>defer\_simple.so</code> file to the location where your OpenVPN plugins are stored.


### Manually installing the Golang binary

To manually install the binary, copy the <code>okta\_openvpn</code>, <code>okta\_pinset.cfg</code>, and <code>okta\_openvpn.ini</code> files to the location where your OpenVPN plugin scripts are stored.


## Make sure that OpenVPN has a tempory directory

In OpenVPN, the "deferred plugin" model requires the use of temporary files to work. It is recommended that these temporary files be stored in a directory that only OpenVPN has access to. The default location for this directory is <code>/etc/openvpn/tmp</code>. If this directory doesn't exist, create it using this command:

```shell
$ sudo mkdir /etc/openvpn/tmp
```

Use the [chown](https://en.wikipedia.org/wiki/Chown) and [chmod](https://en.wikipedia.org/wiki/Chmod) commands to set permissions approprate to your setup (The user that runs OpenVPN should be owner and only writer).


## Configure the Okta OpenVPN plugin

The Okta OpenVPN plugin is configured via the <code>okta\_openvpn.ini</code> file. You **must** update this file with the configuration options for your Okta organization for the plugin to work.

If you installed the Okta OpenVPN plugin to the default location, run this command to edit your configuration file.

```shell
$ sudo $EDITOR /etc/openvpn/okta_openvpn.ini
```


## Configure OpenVPN to use the C Plugin

Set up OpenVPN to call the Okta plugin by adding the following lines to your OpenVPN <code>server.conf</code> configuration file:

```ini
plugin /usr/lib/openvpn/plugins/defer_simple.so /usr/lib/openvpn/plugins/okta_openvpn
tmp-dir "/etc/openvpn/tmp"
```

The default location for OpenVPN configuration files is <code>/etc/openvpn/server.conf</code>

# Contact

Updates or corrections to this document are very welcome. Feel free to send me [pull requests](https://help.github.com/articles/using-pull-requests/) with suggestions.
