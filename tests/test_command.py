import subprocess
import sys
import unittest


class TestOktaOpenVPNCommand(unittest.TestCase):

    def test_true(self):
        self.assertEquals(True, True)

    def test_command(self):
        rv = subprocess.call(["/bin/bash",
                              "tests/test_command.sh"])
        self.assertEquals(rv, 0)
