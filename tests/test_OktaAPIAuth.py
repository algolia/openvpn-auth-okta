import sys
import os
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
from okta_openvpn import OktaAPIAuth
import logging


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
        herokuapp_dot_com_pin = '2hLOYtjSs5a3Jxy5GVM5EMuqa3JHhR6gM99EoaDauug='
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
            'assert_pinset': [herokuapp_dot_com_pin],
            }

    def test_true(self):
        self.assertEquals(True, True)

    def test_okta_url_cleaned(self):
        config = self.config
        url_with_trailing_slash = "{}/".format(self.okta_url)
        config['okta_url'] = url_with_trailing_slash
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, True)

        url_with_path = "{}/api/v1".format(self.okta_url)
        config['okta_url'] = url_with_path
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, True)

    # OktaAPIAuth.auth() tests:
    def test_username_empty(self):
        config = self.config
        config['username'] = ''
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('Missing username or password', last_error)

    def test_username_None(self):
        config = self.config
        config['username'] = None
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('Missing username or password', last_error)

    def test_password_empty(self):
        config = self.config
        config['password'] = ''
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('Missing username or password', last_error)

    def test_password_None(self):
        config = self.config
        config['password'] = None
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('Missing username or password', last_error)

    def test_invalid_no_token(self):
        config = self.config
        config['password'] = 'Testing1'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('No second factor found for username', last_error)

    def test_invalid_url(self):
        config = self.config
        config['okta_url'] = 'http://127.0.0.1:86753'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['error'][-1:][0]
        self.assertIn('Error connecting to the Okta API', last_error)

    def test_invalid_password(self):
        config = self.config
        config['username'] = 'fake_user@example.com'
        config['password'] = 'BADPASSWORD123456'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        expected = 'pre-authentication failed: Authentication failed'
        self.assertIn(expected, last_error)

    def test_valid_user_no_mfa(self):
        config = self.config
        config['username'] = 'Fox.Mulder@ic.fbi.example.com'
        config['password'] = 'trustno1'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, True)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('authenticated without MFA', last_error)

    def test_valid_user_must_enroll_mfa(self):
        config = self.config
        config['username'] = 'user_MFA_ENROLL@example.com'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('needs to enroll first', last_error)

    def test_valid_token(self):
        config = self.config
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, True)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('now authenticated with MFA via Okta API', last_error)

    def test_invalid_token(self):
        config = self.config
        config['password'] = 'Testing1654321'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['debug'][-1:][0]
        self.assertIn('MFA token authentication failed', last_error)

    def test_password_expired(self):
        config = self.config
        config['username'] = 'user_PASSWORD_EXPIRED@example.com'
        okta = OktaAPIAuth(**config)
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['info'][-1:][0]
        self.assertIn('is not allowed to authenticate', last_error)

    def test_unexpected_error(self):
        config = self.config
        okta = OktaAPIAuth(**config)

        def doauth_fail(a, b):
            raise Exception('Mocked exception')

        okta.doauth = doauth_fail
        auth = okta.auth()
        self.assertEquals(auth, False)
        last_error = self.okta_log_messages['error'][-1:][0]
        self.assertIn('Unexpected error with the Okta API', last_error)

    # test_invalid_okta_api_token
    # "authentication filed for unknown reason"

    # test_other_auth_failure_reason (locked, etc)
    # "not allowed to authenticate"
