import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import subprocess


class TestOktaOpenVPNCommand(unittest.TestCase):

    def test_true(self):
        self.assertEquals(True, True)

    def test_command(self):
        rv = subprocess.call(["/bin/bash",
                              "tests/test_command.sh"])
        self.assertEquals(rv, 0)
