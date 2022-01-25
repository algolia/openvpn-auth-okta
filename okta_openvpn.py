#!/usr/bin/env python3
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com

# pylint: disable=C0116,C0115,C0114

import configparser
from configparser import MissingSectionHeaderError
import base64
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import stat
import sys
import time
import urllib.parse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import certifi
import urllib3

from okta_pinset import okta_pinset

VERSION = "1.0.0"
# OktaOpenVPN/0.10.0 (Darwin 12.4.0) CPython/2.7.5
USER_AGENT = ("OktaOpenVPN/{version} "
              "({system} {system_version}) "
              "{implementation}/{python_version}").format(
                  version=VERSION,
                  system=platform.uname()[0],
                  system_version=platform.uname()[2],
                  implementation=platform.python_implementation(),
                  python_version=platform.python_version())

log = logging.getLogger('okta_openvpn')
log.setLevel(logging.DEBUG)
LOG_FMT = "%(module)s[%(process)d]: %(message)s"
errlog = logging.StreamHandler()
errlog.setFormatter(logging.Formatter(LOG_FMT))
log.addHandler(errlog)


class PinError(Exception):
    """Raised when a pin isn't found in a certificate"""


class UnknownControlFileError(Exception):
    """Raised when the control file is None"""


class ControlFilePermissionsError(Exception):
    """Raised when the control file or containing directory have bad permissions"""


class PublicKeyPinsetConnectionPool(urllib3.HTTPSConnectionPool):
    def __init__(self, *args, **kwargs):
        self.pinset = kwargs.pop('assert_pinset', None)
        super().__init__(*args, **kwargs)

    def _validate_conn(self, conn):
        super()._validate_conn(conn)
        if not conn.is_verified:
            raise Exception("Unexpected verification error.")

        cert = conn.sock.getpeercert(binary_form=True)
        public_key = x509.load_der_x509_certificate(
            cert,
            default_backend()).public_key()
        public_key_raw = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_sha256 = hashlib.sha256(public_key_raw).digest()
        public_key_sha256_base64 = base64.b64encode(public_key_sha256)

        if public_key_sha256_base64.decode() not in self.pinset:
            pin_failure_message = (
                'Refusing to authenticate '
                'because host {remote_host} failed '
                'a TLS public key pinning check. '
                'Please contact support@okta.com with this error message'
            ).format(remote_host=conn.host)
            log.critical(pin_failure_message)
            raise PinError("Public Key not found in pinset!")


class OktaAPIAuth():
    def __init__(self, okta_url, okta_token,
                 username, password, client_ipaddr,
                 mfa_push_delay_secs=None,
                 mfa_push_max_retries=None,
                 assert_pinset=None):
        passcode_len = 6
        self.okta_url = None
        self.okta_token = okta_token
        self.username = username
        self.password = password
        self.client_ipaddr = client_ipaddr
        self.passcode = None
        self.okta_urlparse = urllib.parse.urlparse(okta_url)
        self.mfa_push_delay_secs = mfa_push_delay_secs
        self.mfa_push_max_retries = mfa_push_max_retries
        if assert_pinset is None:
            assert_pinset = okta_pinset
        url_new = (self.okta_urlparse.scheme,
                   self.okta_urlparse.netloc,
                   '', '', '', '')
        self.okta_url = urllib.parse.urlunparse(url_new)

        # If the password provided by the user is longer than a OTP (6 cars)
        # and the last 6 caracters are digits
        # then extract the user password (first) and the OTP
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
            'user-agent': USER_AGENT,
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
        retp = False

        invalid_username_or_password = (
            username is None or
            username == '' or
            password is None or
            password == '')
        if invalid_username_or_password:
            log.error("Missing username or password for user: %s (%s) - "
                      "Reported username may be 'None' due to this",
                      username, self.client_ipaddr)
            return False

        if not self.passcode:
            log.info("[%s] No TOTP found in password", username)

        log.debug("[%s] Authenticating", username)
        try:
            retp = self.preauth()
        except Exception as err1:
            log.error('[%s] Error connecting to the Okta API: %s',
                      username, err1)
            return False
        # Check for erros from Okta
        if 'errorCauses' in retp:
            msg = retp['errorSummary']
            log.info('[%s] pre-authentication failed: %s', username, msg)
            return False
        if 'status' in retp:
            status = retp['status']
        # Check authentication status from Okta
        if status == "SUCCESS":
            log.info('[%s] allowed without MFA - refused', username)
            return False
        if status in ["MFA_ENROLL", "MFA_ENROLL_ACTIVATE"]:
            log.info('[%s] user needs to enroll first', username)
            return False
        if status in ["MFA_REQUIRED", "MFA_CHALLENGE"]:
            log.debug("[%s] user password validates, checking second factor",
                      username)
            res = None
            supported_factor_types = ["token:software:totp", "push"]
            for factor in retp['_embedded']['factors']:
                if factor['factorType'] not in supported_factor_types:
                    continue
                fid = factor['id']
                state_token = retp['stateToken']
                try:
                    res = self.doauth(fid, state_token)
                    check_count = 0
                    fctr_rslt = 'factorResult'
                    while fctr_rslt in res and res[fctr_rslt] == 'WAITING':
                        time.sleep(float(self.mfa_push_delay_secs))
                        res = self.doauth(fid, state_token)
                        check_count += 1
                        if check_count > int(self.mfa_push_max_retries):
                            log.info('[%s] User MFA push timed out', username)
                            return False
                except Exception as err2:
                    log.error('[%s] Unexpected error with the Okta API: %s', username, err2)
                    return False
                if 'status' in res and res['status'] == 'SUCCESS':
                    log.info("[%s] User is now authenticated with MFA via Okta API", username)
                    return True
            if 'errorCauses' in res:
                msg = res['errorCauses'][0]['errorSummary']
                log.debug('[%s] User MFA token authentication failed: %s', username, msg)
            return False

        log.info("[%s] User is not allowed to authenticate: %s", username, status)
        return False


class OktaOpenVPNValidator():
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
        # These can be modified in the 'okta_openvpn.ini' file.
        # By default, we retry for 2 minutes:
        self.mfa_push_max_retries = "20"
        self.mfa_push_delay_secs = "3"

    def read_configuration_file(self):
        cfg_path_defaults = [
            '/etc/openvpn/okta_openvpn.ini',
            '/etc/okta_openvpn.ini',
            'okta_openvpn.ini']
        cfg_path = cfg_path_defaults
        parser_defaults = {
            'AllowUntrustedUsers': self.always_trust_username,
            'UsernameSuffix': self.username_suffix,
            'MFAPushMaxRetries': self.mfa_push_max_retries,
            'MFAPushDelaySeconds': self.mfa_push_delay_secs,
            }
        if self.config_file:
            cfg_path = []
            cfg_path.append(self.config_file)
        for cfg_file in cfg_path:
            if os.path.isfile(cfg_file):
                try:
                    cfg = configparser.RawConfigParser(defaults=parser_defaults)
                    cfg.read(cfg_file)
                    self.site_config = {
                        'okta_url': cfg.get('OktaAPI', 'Url'),
                        'okta_token': cfg.get('OktaAPI', 'Token'),
                        'mfa_push_max_retries': cfg.get('OktaAPI',
                                                        'MFAPushMaxRetries'),
                        'mfa_push_delay_secs': cfg.get('OktaAPI',
                                                       'MFAPushDelaySeconds'),
                        }
                    always_trust_username = cfg.get(
                        'OktaAPI',
                        'AllowUntrustedUsers')
                    if always_trust_username == 'True':
                        self.always_trust_username = True
                    self.username_suffix = cfg.get('OktaAPI', 'UsernameSuffix')
                    return True
                except MissingSectionHeaderError as err:
                    log.debug(err)
        if 'okta_url' not in self.site_config and \
           'okta_token' not in self.site_config:
            log.critical("Failed to load config")
            return False
        return True

    def load_environment_variables(self):
        if 'okta_url' not in self.site_config:
            log.critical('OKTA_URL not defined in configuration')
            return False
        if 'okta_token' not in self.site_config:
            log.critical('OKTA_TOKEN not defined in configuration')
            return False
        # Taken from a validated VPN client-side SSL certificate
        username = self.env.get('username')
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
        for item in ['mfa_push_max_retries', 'mfa_push_delay_secs']:
            if item in self.site_config:
                self.okta_config[item] = self.site_config[item]
        assert_pin = self.env.get('assert_pin')
        if assert_pin:
            self.okta_config['assert_pinset'] = [assert_pin]
        return True

    def authenticate(self):
        if not self.username_trusted:
            log.warning("[%s] User is not trusted - failing",
                        self.okta_config['username'])
            return False
        try:
            okta = self.cls(**self.okta_config)
            self.user_valid = okta.auth()
            return self.user_valid
        except Exception as exception:
            log.error(
                "[%s] User at %s authentication failed, "
                "because %s() failed unexpectedly - %s",
                self.okta_config['username'],
                self.okta_config['client_ipaddr'],
                self.cls.__name__,
                exception
            )
        return False

    def check_control_file_permissions(self):
        if self.control_file is None:
            raise UnknownControlFileError()
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
        try:
            with open(self.control_file, 'w') as contf:
                if self.user_valid:
                    contf.write('1')
                else:
                    contf.write('0')
        except IOError:
            log.critical("Failed to write to OpenVPN control file '%s'",
                         self.control_file)

    def run(self):
        self.read_configuration_file()
        self.load_environment_variables()
        self.authenticate()
        self.write_result_to_control_file()


# This is tested by test_command.sh via tests/test_command.py
if __name__ == "__main__":  # pragma: no cover
    validator = OktaOpenVPNValidator()
    validator.run()
    if validator.user_valid:
        sys.exit(0)
    else:
        sys.exit(1)
