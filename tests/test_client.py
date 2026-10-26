"""The SDK against a real AgentWarden web server (loopback, temp data dir)."""

import os
import pathlib
import tempfile
import threading
import unittest

from agentwarden import web
from agentwarden.client import AgentWarden, AgentWardenError, Denied

ROOT = pathlib.Path(__file__).resolve().parent.parent


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PYTHONPATH"] = str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")
        cls.tmp = tempfile.TemporaryDirectory()
        web.Handler.log_message = lambda *args: None
        cls.srv = web.make_server("127.0.0.1", 0, pathlib.Path(cls.tmp.name), env_keys="sk_test")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        w = AgentWarden(cls.url, "sk_test")
        w._call(
            "role-add", {"name": "buyer", "allow": ["read:crm/*", "spend:stripe/*"], "limit": ["spend:stripe/*=50"]}
        )
        w._call("agent-add", {"agent_id": "bot", "owner": "ops", "role": ["buyer"]})
        cls.token = w.issue_token("bot")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def test_allow_deny_and_spend_limit(self):
        w = AgentWarden(self.url, "sk_test")
        self.assertTrue(w.check(self.token, "read", "crm/tickets/1")[0])
        self.assertFalse(w.check(self.token, "send", "email/outbox")[0])
        w.require(self.token, "spend", "stripe/charges", amount=40)
        with self.assertRaises(Denied):
            w.require(self.token, "spend", "stripe/charges", amount=500)

    def test_bad_key_and_dead_server_fail_closed(self):
        with self.assertRaises(AgentWardenError):
            AgentWarden(self.url, "sk_wrong").check(self.token, "read", "crm/x")
        with self.assertRaises(AgentWardenError):
            AgentWarden("http://127.0.0.1:9", "sk_test", timeout=2).check(self.token, "read", "crm/x")

    def test_garbage_token_is_denied(self):
        allowed, reason = AgentWarden(self.url, "sk_test").check("not-a-token", "read", "crm/x")
        self.assertFalse(allowed)
        self.assertIn("token", reason)


if __name__ == "__main__":
    unittest.main()
