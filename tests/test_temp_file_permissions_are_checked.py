import os
import sys
import tempfile
import unittest

from mock import MagicMock
import urllib3

from okta_openvpn import OktaAPIAuth
from okta_openvpn import OktaOpenVPNValidator
from okta_openvpn import ControlFilePermissionsError

from tests.shared import OktaTestCase
from tests.shared import MockEnviron


class TestTempFilePermissions(OktaTestCase):
    def setUp(self):
        super(TestTempFilePermissions, self).setUp()

        self.expected_messages = [
            'efusing to authenticate',
            'must not be',
            'writable',
            ]

    def test_control_file_has_bad_permissions(self):
        cfg = self.config

        tmp = tempfile.NamedTemporaryFile()

        os.chmod(tmp.name, 0777)

        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password'],
            'auth_control_file': tmp.name,
            'assert_pin': self.herokuapp_dot_com_pin,
            })
        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env

        self.assertRaises(ControlFilePermissionsError, validator.run)
        last_error = self.okta_log_messages['critical'][-1:][0]
        for msg in self.expected_messages:
            self.assertIn(msg, last_error)
        tmp.close()

    def test_control_file_bad_permissions_permutations(self):
        cfg = self.config
        modes = [
            0606,
            0660,
            0622,
            ]
        for mode in modes:
            tmp = tempfile.NamedTemporaryFile()
            os.chmod(tmp.name, mode)

            env = MockEnviron({
                'common_name': self.config['username'],
                'password': self.config['password'],
                'auth_control_file': tmp.name,
                'assert_pin': self.herokuapp_dot_com_pin,
                })
            validator = OktaOpenVPNValidator()
            validator.site_config = cfg
            validator.env = env
            self.assertRaises(ControlFilePermissionsError, validator.run)
            tmp.close()

    def test_control_file_directory_has_bad_permissions(self):
        cfg = self.config

        tmp_dir = tempfile.mkdtemp()
        tmp = tempfile.NamedTemporaryFile(dir=tmp_dir)
        os.chmod(tmp_dir, 0777)
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password'],
            'auth_control_file': tmp.name,
            'assert_pin': self.herokuapp_dot_com_pin,
            })
        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env

        msgs = self.expected_messages
        msgs.append('directory containing')

        self.assertRaises(ControlFilePermissionsError, validator.run)
        last_error = self.okta_log_messages['critical'][-1:][0]
        for msg in msgs:
            self.assertIn(msg, last_error)
        tmp.close()
        os.rmdir(tmp_dir)
