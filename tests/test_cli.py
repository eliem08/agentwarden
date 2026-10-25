"""CLI smoke tests, generated from _tools/smoke.json.

Every documented command must run in-process, exit with a domain status code
(0 ok, 1 nothing found / failing grade, 2 denied) instead of crashing, and print
output a legacy Windows console (cp1252) can encode.
"""

import contextlib
import io
import pathlib
import tempfile
import unittest

from agentwarden.__main__ import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMMANDS = [
    ["--store", "{tmp}/okta.json", "role", "add", "support", "--allow", "read:crm/*", "--deny", "read:crm/payroll*"],
    ["--store", "{tmp}/okta.json", "agent", "add", "bot1", "--owner", "a@x.com", "--role", "support"],
    ["--store", "{tmp}/okta.json", "agent", "list"],
    ["--store", "{tmp}/okta.json", "role", "list"],
]


class CliSmokeTests(unittest.TestCase):
    def test_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            for template in COMMANDS:
                argv = [a.replace("{root}", str(ROOT)).replace("{tmp}", tmp) for a in template]
                with self.subTest(argv=template):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                        code = main(argv)
                    self.assertIn(code, (0, 1, 2))
                    self.assertTrue(out.getvalue().strip(), "command printed nothing")
                    out.getvalue().encode("cp1252")


if __name__ == "__main__":
    unittest.main()
