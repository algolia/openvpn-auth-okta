#!/usr/bin/env python2
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com

import ConfigParser
from ConfigParser import MissingSectionHeaderError
import base64
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import stat
import sys
import urlparse

import M2Crypto
import certifi
import urllib3

from okta_pinset import okta_pinset

version = "0.9.2"
# OktaOpenVPN/0.9.0 (Darwin 12.4.0) CPython/2.7.5
user_agent = ("OktaOpenVPN/{version} "
              "({system} {system_version}) "
              "{implementation}/{python_version}").format(
                  version=version,
                  system=platform.uname()[0],
                  system_version=platform.uname()[2],
                  implementation=platform.python_implementation(),
                  python_version=platform.python_version())
log = logging.getLogger('okta_openvpn')
log.setLevel(logging.DEBUG)
syslog = logging.handlers.SysLogHandler()
# http://stackoverflow.com/a/18297526
syslog_fmt = "%(module)s-%(processName)s[%(process)d]: %(name)s: %(message)s"
syslog.setFormatter(logging.Formatter(syslog_fmt))
log.addHandler(syslog)
# # Uncomment to enable logging to STDERR
# errlog = logging.StreamHandler()
# errlog.setFormatter(logging.Formatter(syslog_fmt))
# log.addHandler(errlog)
# # Uncomment to enable logging to a file
# filelog = logging.FileHandler('/tmp/okta_openvpn.log')
# filelog.setFormatter(logging.Formatter(syslog_fmt))
# log.addHandler(filelog)


class PinError(Exception):
    "Raised when a pin isn't found in a certificate"
    pass


class ControlFilePermissionsError(Exception):
    "Raised when the control file or containing directory have bad permissions"
    pass


class PublicKeyPinsetConnectionPool(urllib3.HTTPSConnectionPool):
    def __init__(self, *args, **kwargs):
        self.pinset = kwargs.pop('assert_pinset', None)
        super(PublicKeyPinsetConnectionPool, self).__init__(*args, **kwargs)

    def _validate_conn(self, conn):
        super(PublicKeyPinsetConnectionPool, self)._validate_conn(conn)
        if not conn.is_verified:
            raise Exception("Unexpected verification error.")

        der = conn.sock.getpeercert(binary_form=True)
        x509 = M2Crypto.X509.load_cert_string(der, M2Crypto.X509.FORMAT_DER)
        mem = M2Crypto.BIO.MemoryBuffer()
        x509.get_pubkey().get_rsa().save_pub_key_bio(mem)
        public_key = mem.getvalue()
        public_key_base64 = ''.join(public_key.split("\n")[1:-2])
        public_key_raw = base64.b64decode(public_key_base64)
        public_key_sha265 = hashlib.sha256(public_key_raw).digest()
        public_key_sha265_base64 = base64.b64encode(public_key_sha265)

        if public_key_sha265_base64 not in self.pinset:
            pin_failure_message = (
                'Refusing to authenticate '
                'because host {remote_host} failed '
                'a TLS public key pinning check. '
                'Please contact support@okta.com with this error message'
            ).format(remote_host=conn.host)
            log.critical(pin_failure_message)
            raise PinError("Public Key not found in pinset!")


class OktaAPIAuth(object):
    def __init__(self, okta_url, okta_token,
                 username, password, client_ipaddr,
                 assert_pinset=None):
        passcode_len = 6
        self.okta_url = None
        self.okta_token = okta_token
        self.username = username
        self.password = password
        self.client_ipaddr = client_ipaddr
        self.passcode = None
        self.okta_urlparse = urlparse.urlparse(okta_url)
        if assert_pinset is None:
            assert_pinset = okta_pinset
        url_new = (self.okta_urlparse.scheme,
                   self.okta_urlparse.netloc,
                   '', '', '', '')
        self.okta_url = urlparse.urlunparse(url_new)
        if password and len(password) > passcode_len:
            last = password[-passcode_len:]
            if last.isdigit():
                self.passcode = last
                self.password = password[:-passcode_len]
        self.pool = PublicKeyPinsetConnectionPool(
            self.okta_urlparse.hostname,
            self.okta_urlparse.port,
            assert_pinset=assert_pinset,
            cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where(),
        )

    def okta_req(self, path, data):
        ssws = "SSWS {token}".format(token=self.okta_token)
        headers = {
            'user-agent': user_agent,
            'content-type': 'application/json',
            'accept': 'application/json',
            'authorization': ssws,
            }
        url = "{base}/api/v1{path}".format(base=self.okta_url, path=path)
        req = self.pool.urlopen(
            'POST',
            url,
            headers=headers,
            body=json.dumps(data)
        )
        return json.loads(req.data)

    def preauth(self):
        path = "/authn"
        data = {
            'username': self.username,
            'password': self.password,
        }
        return self.okta_req(path, data)

    def doauth(self, fid, state_token):
        path = "/authn/factors/{fid}/verify".format(fid=fid)
        data = {
            'fid': fid,
            'stateToken': state_token,
            'passCode': self.passcode,
        }
        return self.okta_req(path, data)

    def auth(self):
        username = self.username
        password = self.password
        status = False
        rv = False

        invalid_username_or_password = (
            username is None or
            username == '' or
            password is None or
            password == '')
        if invalid_username_or_password:
            log.info("Missing username or password for user: %s (%s) - "
                     "Reported username may be 'None' due to this", username, self.client_ipaddr)
            return False

        if not self.passcode:
            log.info("No second factor found for username %s", username)

        log.debug("Authenticating username %s", username)
        try:
            rv = self.preauth()
        except Exception, s:
            log.error('Error connecting to the Okta API: %s', s)
            return False
        if 'errorCauses' in rv:
            msg = rv['errorSummary']
            log.info('User %s pre-authentication failed: %s', self.username, msg)
            return False
        elif 'status' in rv:
            status = rv['status']

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
                if factor['factorType'] != "token:software:totp":
                    continue
                fid = factor['id']
                state_token = rv['stateToken']
                try:
                    res = self.doauth(fid, state_token)
                except Exception, s:
                    log.error('Unexpected error with the Okta API: %s', s)
                    return False
                if 'status' in res and res['status'] == 'SUCCESS':
                    log.info("User %s is now authenticated "
                             "with MFA via Okta API", self.username)
                    return True

            if 'errorCauses' in res:
                msg = res['errorCauses'][0]['errorSummary']
                log.debug('User %s MFA token authentication failed: %s', self.username, msg)
            return False
        else:
            log.info("User %s is not allowed to authenticate: %s", self.username, status)
            return False


class OktaOpenVPNValidator(object):
    def __init__(self):
        self.cls = OktaAPIAuth
        self.username_trusted = False
        self.user_valid = False
        self.control_file = None
        self.site_config = {}
        self.config_file = None
        self.env = os.environ
        self.okta_config = {}
        self.username_suffix = None
        self.always_trust_username = False

    def read_configuration_file(self):
        cfg_path_defaults = [
            '/etc/openvpn/okta_openvpn.ini',
            '/etc/okta_openvpn.ini',
            'okta_openvpn.ini']
        cfg_path = cfg_path_defaults
        parser_defaults = {
            'AllowUntrustedUsers': self.always_trust_username,
            'UsernameSuffix': self.username_suffix,
            }
        if self.config_file:
            cfg_path = []
            cfg_path.append(self.config_file)
        log.debug(cfg_path)
        for cfg_file in cfg_path:
            if os.path.isfile(cfg_file):
                try:
                    cfg = ConfigParser.ConfigParser(defaults=parser_defaults)
                    cfg.read(cfg_file)
                    self.site_config = {
                        'okta_url': cfg.get('OktaAPI', 'Url'),
                        'okta_token': cfg.get('OktaAPI', 'Token'),
                        }
                    always_trust_username = cfg.get(
                        'OktaAPI',
                        'AllowUntrustedUsers')
                    if always_trust_username == 'True':
                        self.always_trust_username = True
                    self.username_suffix = cfg.get('OktaAPI', 'UsernameSuffix')
                    return True
                except MissingSectionHeaderError, e:
                    log.debug(e)
        if 'okta_url' not in self.site_config and \
           'okta_token' not in self.site_config:
            log.critical("Failed to load config")
            return False

    def load_environment_variables(self):
        if 'okta_url' not in self.site_config:
            log.critical('OKTA_URL not defined in configuration')
            return False
        if 'okta_token' not in self.site_config:
            log.critical('OKTA_TOKEN not defined in configuration')
            return False
        # Taken from a validated VPN client-side SSL certificate
        username = self.env.get('common_name')
        password = self.env.get('password')
        client_ipaddr = self.env.get('untrusted_ip', '0.0.0.0')
        # Note:
        #   username_trusted is True if the username comes from a certificate
        #
        #   Meaning, if self.common_name is NOT set, but self.username IS,
        #   then self.username_trusted will be False
        if username is not None:
            self.username_trusted = True
        else:
            # This is set according to what the VPN client has sent us
            username = self.env.get('username')
        if self.always_trust_username:
            self.username_trusted = self.always_trust_username
        if self.username_suffix and '@' not in username:
            username = username + '@' + self.username_suffix
        self.control_file = self.env.get('auth_control_file')
        if self.control_file is None:
            log.info(("No control file found, "
                      "if using a deferred plugin "
                      "authentication will stall and fail."))
        self.okta_config = {
            'okta_url': self.site_config['okta_url'],
            'okta_token': self.site_config['okta_token'],
            'username': username,
            'password': password,
            'client_ipaddr': client_ipaddr,
        }
        assert_pin = self.env.get('assert_pin')
        if assert_pin:
            self.okta_config['assert_pinset'] = [assert_pin]

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

    def check_control_file_permissions(self):
        file_mode = os.stat(self.control_file).st_mode
        if file_mode & stat.S_IWGRP or file_mode & stat.S_IWOTH:
            log.critical(
                'Refusing to authenticate. The file %s'
                ' must not be writable by non-owners.',
                self.control_file
            )
            raise ControlFilePermissionsError()
        dir_name = os.path.split(self.control_file)[0]
        dir_mode = os.stat(dir_name).st_mode
        if dir_mode & stat.S_IWGRP or dir_mode & stat.S_IWOTH:
            log.critical(
                'Refusing to authenticate.'
                ' The directory containing the file %s'
                ' must not be writable by non-owners.',
                self.control_file
            )
            raise ControlFilePermissionsError()

    def write_result_to_control_file(self):
        self.check_control_file_permissions()
        if self.user_valid:
            try:
                with open(self.control_file, 'w') as f:
                    f.write('1')
            except:
                pass
            return
        try:
            with open(self.control_file, 'w') as f:
                f.write('0')
        except:
            pass

    def run(self):
        self.read_configuration_file()
        self.load_environment_variables()
        self.authenticate()
        self.write_result_to_control_file()


def return_error_code_for(validator):
    if validator.user_valid:
        sys.exit(0)
    else:
        sys.exit(1)

# This is tested by test_command.sh via tests/test_command.py
if __name__ == "__main__":  # pragma: no cover
    validator = OktaOpenVPNValidator()
    validator.run()
    return_error_code_for(validator)
