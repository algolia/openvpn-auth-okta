import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
from okta_openvpn import (
    OktaAPIAuth,
    PinError
    )
import logging
import os

import urllib3
from mock import MagicMock


class TestOktaAPIAuthTLSPinning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning
        logging.captureWarnings(True)

    def setUp(self):
        super(TestOktaAPIAuthTLSPinning, self).setUp()
        self.okta_url = os.environ.get(
            'okta_url_mock',
            'https://mocked-okta-api.herokuapp.com')
        self.okta_token = 'mocked-token-for-openvpn'
        self.config = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            'username': 'user_MFA_REQUIRED@example.com',
            'password': 'Testing1123456',
            'client_ipaddr': '10.0.0.1',
            }
        self.example_dot_com_pin = (
            'wiviOfSDwIlXvBBiGcwtOsGjCN+73Qo2Xxe5NRI0zwA=')
        self.herokuapp_dot_com_pin = (
            '2hLOYtjSs5a3Jxy5GVM5EMuqa3JHhR6gM99EoaDauug=')

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

    def test_validate_conn_checks_is_verified(self):
        from okta_openvpn import PublicKeyPinsetConnectionPool
        pool = PublicKeyPinsetConnectionPool('example.com', 443)
        conn = MagicMock()
        conn.is_verified = False
        self.assertRaises(Exception, pool._validate_conn, conn)
