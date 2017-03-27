import os
import unittest
import logging
from okta_openvpn import OktaAPIAuth


class OktaTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(OktaTestCase, cls).setUpClass()
        okta_log = logging.getLogger('okta_openvpn')
        cls._okta_log_handler = MockLoggingHandler(level='DEBUG')
        okta_log.addHandler(cls._okta_log_handler)
        cls.okta_log_messages = cls._okta_log_handler.messages
        # https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning
        logging.captureWarnings(True)

    def setUp(self):
        super(OktaTestCase, self).setUp()
        self._okta_log_handler.reset()  # So each test is independent
        # # Here is how a pin like those below may be generated:
        # echo -n | openssl s_client -connect example.com:443 |
        # openssl x509 -noout -pubkey |
        # openssl rsa  -pubin -outform der |
        # openssl dgst -sha256 -binary | base64
        self.example_dot_com_pin = (
            'wiviOfSDwIlXvBBiGcwtOsGjCN+73Qo2Xxe5NRI0zwA=')
        self.herokuapp_dot_com_pin = (
            '2hLOYtjSs5a3Jxy5GVM5EMuqa3JHhR6gM99EoaDauug=')
        self.okta_url = os.environ.get(
            'okta_url_mock',
            'https://mocked-okta-api.herokuapp.com')
        self.okta_token = 'mocked-token-for-openvpn'
        self.username_prefix = 'user_MFA_REQUIRED'
        self.username_suffix = 'example.com'
        self.config = {
            'okta_url': self.okta_url,
            'okta_token': self.okta_token,
            'username': "{}@{}".format(self.username_prefix,
                                       self.username_suffix),
            'password': 'Testing1123456',
            'client_ipaddr': '4.2.2.2',
            }
        self.mfa_push_delay_secs = 1


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
