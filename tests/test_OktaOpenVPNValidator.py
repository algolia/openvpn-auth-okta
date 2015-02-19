import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import logging
import tempfile
import os
from mock import MagicMock

from okta_openvpn import OktaOpenVPNValidator
from okta_openvpn import OktaAPIAuth
import okta_openvpn


class ThrowsErrorOktaAPI(OktaAPIAuth):
    def __init__(self, *args, **kwargs):
        raise Exception()


class MockLoggingHandler(logging.Handler):
    """Mock logging handler to check for expected logs.

    Messages are available from an instance's ``messages`` dict,
    in order, indexed by a lowercase log level string
    (e.g., 'debug', 'info', etc.).
    """

    def __init__(self, *args, **kwargs):
        self.messages = {'debug': [], 'info': [], 'warning': [], 'error': [],
                         'critical': []}
        super(MockLoggingHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        "Store a message from ``record`` in the instance's ``messages`` dict."
        self.acquire()
        try:
            self.messages[record.levelname.lower()].append(record.getMessage())
        finally:
            self.release()

    def reset(self):
        self.acquire()
        try:
            for message_list in self.messages.values():
                message_list = []
        finally:
            self.release()


class MockEnviron:
    def __init__(self, values):
        self.values = values

    def get(self, k, v=None):
        if k in self.values:
            return self.values[k]
        elif v:
            return v
        else:
            return None


class TestOktaAPIAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestOktaAPIAuth, cls).setUpClass()
        okta_log = logging.getLogger('okta_openvpn')
        cls._okta_log_handler = MockLoggingHandler(level='DEBUG')
        okta_log.addHandler(cls._okta_log_handler)
        cls.okta_log_messages = cls._okta_log_handler.messages

    def setUp(self):
        super(TestOktaAPIAuth, self).setUp()
        self._okta_log_handler.reset()  # So each test is independent
        self.herokuapp_dot_com_pin = (
            '2hLOYtjSs5a3Jxy5GVM5EMuqa3JHhR6gM99EoaDauug=')
        self.okta_url = os.environ.get(
            'okta_url_mock',
            'https://mocked-okta-api.herokuapp.com')
        self.okta_token = 'mocked-token-for-openvpn'
        self.config = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            'username': 'user_MFA_REQUIRED@example.com',
            'password': 'Testing1123456',
            'client_ipaddr': '4.2.2.2',
            'assert_pinset': [self.herokuapp_dot_com_pin],
            }

    def test_true(self):
        self.assertEquals(True, True)

    def test_invalid_configuration_file(self):
        validator = OktaOpenVPNValidator()
        validator.config_file = '/dev/false'
        rv = validator.read_configuration_file()
        self.assertEquals(rv, False)
        last_error = self.okta_log_messages['critical'][-1:][0]
        self.assertIn('Failed to load config', last_error)

    def test_no_okta_url(self):
        env = MockEnviron({})
        validator = OktaOpenVPNValidator()
        validator.env = env
        rv = validator.load_environment_variables()
        self.assertEquals(rv, False)
        last_error = self.okta_log_messages['critical'][-1:][0]
        self.assertIn('OKTA_URL not defined', last_error)

    def test_okta_url_no_token(self):
        cfg = {
            'okta_url': self.okta_url
        }
        env = MockEnviron({})
        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env
        rv = validator.load_environment_variables()
        self.assertEquals(rv, False)
        last_error = self.okta_log_messages['critical'][-1:][0]
        self.assertIn('OKTA_TOKEN not defined', last_error)

    def test_no_username_or_password(self):
        cfg = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            }
        env = MockEnviron({})
        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env
        rv = validator.load_environment_variables()
        rv = validator.authenticate()
        self.assertEquals(rv, False)
        last_error = self.okta_log_messages['warning'][-1:][0]
        self.assertIn('is not trusted - failing', last_error)

    def test_with_username_and_password(self):
        cfg = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            }
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password']
            })
        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env
        validator.load_environment_variables()
        validator.okta_config['assert_pinset'] = [self.herokuapp_dot_com_pin]

        rv = validator.authenticate()
        self.assertEquals(rv, True)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('is now authenticated with MFA via Okta API', last_error)

    def test_with_valid_config_file(self):
        config_format = (
            "[OktaAPI]\n"
            "Url: {}\n"
            "Token: {}\n")
        cfg = tempfile.NamedTemporaryFile()
        cfg.file.write(config_format.format(
            self.okta_url,
            self.okta_token))
        cfg.file.seek(0)
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password']
            })
        validator = OktaOpenVPNValidator()
        validator.config_file = cfg.name
        validator.env = env
        validator.read_configuration_file()
        validator.load_environment_variables()
        # Disable Public Key Pinning
        validator.okta_config['assert_pinset'] = [self.herokuapp_dot_com_pin]
        rv = validator.authenticate()
        self.assertEquals(rv, True)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('is now authenticated with MFA via Okta API', last_error)

    def test_with_invalid_config_file(self):
        cfg = tempfile.NamedTemporaryFile()
        cfg.file.write('invalidconfig')
        cfg.file.seek(0)
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password']
            })
        validator = OktaOpenVPNValidator()
        validator.config_file = cfg.name
        validator.env = env
        rv = validator.read_configuration_file()
        self.assertEquals(rv, False)

    def test_return_error_code_true(self):
        validator = OktaOpenVPNValidator()
        validator.user_valid = True
        okta_openvpn.sys = MagicMock()
        okta_openvpn.return_error_code_for(validator)
        okta_openvpn.sys.exit.assert_called_with(0)

    def test_return_error_code_false(self):
        validator = OktaOpenVPNValidator()
        validator.user_valid = False
        okta_openvpn.sys = MagicMock()
        okta_openvpn.return_error_code_for(validator)
        okta_openvpn.sys.exit.assert_called_with(1)

    def test_authenticate_handles_exceptions(self):
        cfg = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            }
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password']
            })
        validator = OktaOpenVPNValidator()
        validator.cls = ThrowsErrorOktaAPI
        validator.site_config = cfg
        validator.env = env
        validator.load_environment_variables()
        rv = validator.authenticate()
        self.assertEquals(rv, False)
        last_error = self.okta_log_messages['error'][-1:][0]
        self.assertIn('authentication failed, because', last_error)

    def test_write_0_to_control_file(self):
        tmp = tempfile.NamedTemporaryFile()
        validator = OktaOpenVPNValidator()
        validator.control_file = tmp.name
        validator.write_result_to_control_file()
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '0')

    def test_write_1_to_control_file(self):
        tmp = tempfile.NamedTemporaryFile()
        validator = OktaOpenVPNValidator()
        validator.user_valid = True
        validator.control_file = tmp.name
        validator.write_result_to_control_file()
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '1')

    def test_write_ro_to_control_file(self):
        tmp = tempfile.NamedTemporaryFile()
        os.chmod(tmp.name, 0400)
        validator = OktaOpenVPNValidator()
        validator.user_valid = True
        validator.control_file = tmp.name
        validator.write_result_to_control_file()
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '')

        tmp.file.seek(0)
        validator.user_valid = False
        validator.write_result_to_control_file()
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '')

    def test_OktaOpenVPNValidator_run(self):
        cfg = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            }
        tmp = tempfile.NamedTemporaryFile()
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password'],
            'auth_control_file': tmp.name,
            'assert_pin': self.herokuapp_dot_com_pin,
            })

        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env

        validator.run()

        self.assertTrue(validator.user_valid)
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '1')
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('is now authenticated with MFA via Okta API', last_error)

    # def test_control_file_world_writeable
    # def test_control_file_ro_gives_error
    # def test_tmp_dir_bad_permissions
