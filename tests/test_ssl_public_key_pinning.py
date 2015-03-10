import sys
import tempfile
import unittest

from mock import MagicMock
import urllib3

from okta_openvpn import OktaAPIAuth
from okta_openvpn import OktaOpenVPNValidator
from okta_openvpn import PinError

from tests.shared import OktaTestCase
from tests.shared import MockEnviron
from tests.shared import MockLoggingHandler


class TestOktaAPIAuthTLSPinning(OktaTestCase):
    def test_connect_to_unencrypted_server(self):
        config = self.config
        config['okta_url'] = 'http://example.com'
        okta = OktaAPIAuth(**config)
        self.assertRaises(urllib3.exceptions.PoolError, okta.preauth)

    def test_connect_to_encrypted_but_unintended_server(self):
        config = self.config
        config['okta_url'] = 'https://example.com'
        okta = OktaAPIAuth(**config)
        self.assertRaises(PinError, okta.preauth)

    def test_connect_to_unintended_server_writes_0_to_control_file(self):
        cfg = self.config
        cfg['okta_url'] = 'https://example.com'

        tmp = tempfile.NamedTemporaryFile()
        env = MockEnviron({
            'common_name': self.config['username'],
            'password': self.config['password'],
            'auth_control_file': tmp.name,
            })

        validator = OktaOpenVPNValidator()
        validator.site_config = cfg
        validator.env = env

        validator.run()

        self.assertFalse(validator.user_valid)
        tmp.file.seek(0)
        rv = tmp.file.read()
        self.assertEquals(rv, '0')

    def test_connect_to_okta_with_good_pins(self):
        config = self.config
        config['okta_url'] = 'https://example.okta.com'
        okta = OktaAPIAuth(**config)
        result = okta.preauth()
        # This is what we'll get since we're sending an invalid token:
        self.assertIn('errorSummary', result)
        self.assertEquals(result['errorSummary'], 'Invalid token provided')

    def test_connect_to_example_with_good_pin(self):
        config = self.config
        config['assert_pinset'] = [self.herokuapp_dot_com_pin]
        okta = OktaAPIAuth(**config)
        result = okta.preauth()
        self.assertIn('status', result)
        self.assertEquals(result['status'], 'MFA_REQUIRED')

    def test_connect_to_example_with_bad_pin(self):
        config = self.config
        config['assert_pinset'] = ['not-a-sha256']
        okta = OktaAPIAuth(**config)
        self.assertRaises(PinError, okta.preauth)

    def test_bad_pin_log_message(self):
        config = self.config
        config['assert_pinset'] = ['not-a-sha256']
        okta = OktaAPIAuth(**config)
        self.assertRaises(PinError, okta.preauth)
        last_error = self.okta_log_messages['critical'][-1:][0]
        messages = [
            'efusing to authenticate',
            'mocked-okta-api.herokuapp.com',
            'TLS public key pinning check',
            'lease contact support@okta.com',
            ]
        for msg in messages:
            self.assertIn(msg, last_error)

    def test_validate_conn_checks_is_verified(self):
        from okta_openvpn import PublicKeyPinsetConnectionPool
        pool = PublicKeyPinsetConnectionPool('example.com', 443)
        conn = MagicMock()
        conn.is_verified = False
        self.assertRaises(Exception, pool._validate_conn, conn)
