import os
import tempfile
import unittest

from agent_okta import Directory, TokenError


class Tests(unittest.TestCase):
    def setUp(self):
        self.d = Directory(secret="s3cret")
        self.d.add_role("support", allow=["read:crm/*", "spend:stripe/*"], deny=["read:crm/payroll*"],
                        spend_limits={"spend:stripe/*": 50})
        self.d.add_agent("bot1", "alice", ["support"])
        self.tok = self.d.issue_token("bot1", ttl=60, now=1000)

    def test_allow_and_deny(self):
        self.assertTrue(self.d.authorize(self.tok, "read", "crm/tickets/1", now=1001)[0])
        ok, reason = self.d.authorize(self.tok, "read", "crm/payroll/x", now=1001)
        self.assertFalse(ok)
        self.assertIn("explicit deny", reason)
        self.assertEqual(self.d.authorize(self.tok, "write", "crm/tickets/1", now=1001), (False, "no matching grant"))

    def test_spend_limit(self):
        self.assertTrue(self.d.authorize(self.tok, "spend", "stripe/charge", amount=20, now=1001)[0])
        self.assertFalse(self.d.authorize(self.tok, "spend", "stripe/charge", amount=80, now=1001)[0])

    def test_expiry_tamper_revoke_disable(self):
        self.assertEqual(self.d.authorize(self.tok, "read", "crm/a", now=2000)[1], "token expired")
        h, b, s = self.tok.split(".")
        self.assertFalse(self.d.authorize(f"{h}.{b}.{s[:-2]}xx", "read", "crm/a", now=1001)[0])
        self.d.revoke(self.tok)
        self.assertEqual(self.d.authorize(self.tok, "read", "crm/a", now=1001)[1], "token revoked")
        self.d.disable_agent("bot1")
        with self.assertRaises(TokenError):
            self.d.issue_token("bot1")

    def test_persistence_and_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "store.json")
            d = Directory(p, secret="k")
            d.add_role("r", allow=["read:*"])
            d.add_agent("a", "o", ["r"])
            d.save()
            d2 = Directory(p, secret="k")
            t = d2.issue_token("a")
            self.assertTrue(d2.authorize(t, "read", "anything")[0])
            self.assertTrue(os.path.exists(p + ".audit.jsonl"))


if __name__ == "__main__":
    unittest.main()
