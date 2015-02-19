<div id="table-of-contents">
<h2>Table of Contents</h2>
<div id="text-table-of-contents">
<ul>
<li><a href="#sec-1">1. Introduction</a></li>
<li><a href="#sec-2">2. Requirements</a></li>
<li><a href="#sec-3">3. Setup and Configuration</a></li>
<li><a href="#sec-4">4. Testing</a></li>
<li><a href="#sec-5">5. Contact</a></li>
</ul>
</div>
</div>



# Introduction<a id="sec-1" name="sec-1"></a>

This is an OpenVPN plugin that authenticates users directly against Okta, with support for MFA.

# Requirements<a id="sec-2" name="sec-2"></a>

This plugin requires that OpenVPN be configured or use in the following ways:

1.  OpenVPN must be configured to call plugins via a deferred call.
2.  OpenVPN clients *must* authenticate using client SSL certificates.
3.  If authenticating using MFA, the end user will authenticate by appending their six-digit MFA token to the end of their password.
    For example, if a user's password is "correcthorsebatterystaple" and their six-digit MFA token is 123456, 
    they would use "correcthorsebatterystaple123456" as the password for their OpenVPN client

# Setup and Configuration<a id="sec-3" name="sec-3"></a>

## Compile the C Plugin<a id="sec-3-1" name="sec-3-1"></a>

Compile the C plugin from this directory using this command:

```shell
$ make
```

## Install required Python packages<a id="sec-3-2" name="sec-3-2"></a>

The Python code in this project depends on the following Python packages:

-   urllib3
-   M2Crypto
-   certifi

If you use [pip](https://en.wikipedia.org/wiki/Pip_%28package_manager%29) to manage your Python packages, you can install these requirements using this command:

```shell
$ sudo pip install urllib3 M3Crypto certifi
```

This project also comes with a <code>requirements.txt</code> file that works nicely with [virtualenv](https://virtualenv.pypa.io/en/latest/).

## Install the Okta OpenVPN plugin<a id="sec-3-3" name="sec-3-3"></a>

You have two options to install the Okta OpenVPN plugin:

1.  For default setups, use <code>make install</code> to run the install for you.
2.  For custom setups, follow the manual installation instructions below.

If you have a default OpenVPN setup, 
where plugins are stored in <code>/usr/lib/openvpn/plugins</code>
and configuration files are stored in <code>/etc/openvpn</code>, then you can use the
<code>make install</code> command to install the Okta OpenVPN plugin:

```shell
$ sudo make install
```

## Manually installing the Okta OpenVPN plugin<a id="sec-3-4" name="sec-3-4"></a>

If you have a custom setup, 
follow the instructions below to install 
the C plugin and Python script that constitute the Okta OpenVPN plugin.

### Manually installing the C Plugin<a id="sec-3-4-1" name="sec-3-4-1"></a>

To manually install the C plugin, copy the <code>defer\_simple.so</code> file to the location where your OpenVPN plugins are stored.

### Manually installing the Python script<a id="sec-3-4-2" name="sec-3-4-2"></a>

To manually install the Python script, copy the <code>okta\_openvpn.py</code>, 
<code>okta\_pinset.py</code>, 
and <code>okta\_openvpn.ini</code> files to the location where your OpenVPN plugin scripts are stored.

## Make sure that OpenVPN has a tempory directory<a id="sec-3-5" name="sec-3-5"></a>

In OpenVPN, the use of a "deferred plugin" requires the use of temporary files. 
It is recommended that these temporary files be stored in a directory that only OpenVPN has access to. 
The default location for this directory is <code>/etc/openvpn/tmp</code>. If this directory doesn't exist, create it using this command:

```shell
$ sudo mkdir /etc/openvpn/tmp
```

Use the [chown](https://en.wikipedia.org/wiki/Chown) and [chmod](https://en.wikipedia.org/wiki/Chmod) commands to set permissions approprate to your setup.

## Configure OpenVPN to use the C Plugin<a id="sec-3-6" name="sec-3-6"></a>

Set up OpenVPN to call the Okta plugin by adding the following lines to your OpenVPN <code>server.conf</code> configuration file:

```ini
plugin /usr/lib/openvpn/plugins/defer_simple.so /usr/lib/openvpn/plugins/okta_openvpn.py
tmp-dir "/etc/openvpn/tmp"
```

The default location for OpenVPN configuration files is <code>/etc/openvpn/server.conf</code>

# Testing<a id="sec-4" name="sec-4"></a>

The code in <code>okta\_openvpn.py</code> has 100% test coverage. Tests are run using the "<code>nosetests</code>" command.

Run the commands below to set up an environment for testing:

```shell
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

Once that is done, run the tests with the <code>nosetests</code> command:

```shell
$ nosetests
```

# Contact<a id="sec-5" name="sec-5"></a>

Updates or corrections to this document are very welcome. Feel free
to send me [pull requests](https://help.github.com/articles/using-pull-requests/) with suggestions.


Additionally, please send me comments or questions via email: &#106;&#111;&#101;&#108;&#046;&#102;&#114;&#097;&#110;&#117;&#115;&#105;&#099;&#064;&#111;&#107;&#116;&#097;&#046;&#099;&#111;&#109;