from okta_openvpn import OktaAPIAuth
from tests.shared import MockLoggingHandler
from tests.shared import OktaTestCase


class TestOktaAPIAuth(OktaTestCase):
    def setUp(self):
        super(TestOktaAPIAuth, self).setUp()
        self.config['assert_pinset'] = [self.herokuapp_dot_com_pin]

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
