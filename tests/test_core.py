import os
import tempfile
import unittest

from agentwarden import Directory, TokenError


class Tests(unittest.TestCase):
    def setUp(self):
        self.d = Directory(secret="s3cret")
        self.d.add_role(
            "support",
            allow=["read:crm/*", "spend:stripe/*"],
            deny=["read:crm/payroll*"],
            spend_limits={"spend:stripe/*": 50},
        )
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

    def test_spend_limit_cannot_be_bypassed_with_nan_inf_or_negative(self):
        for amount in (float("nan"), float("inf"), -500):
            with self.subTest(amount=amount):
                ok, reason = self.d.authorize(self.tok, "spend", "stripe/charge", amount=amount, now=1001)
                self.assertFalse(ok)
                self.assertIn("invalid amount", reason)
        with self.assertRaises(ValueError):
            self.d.add_role("bad", allow=["spend:*"], spend_limits={"spend:*": float("nan")})

    def test_no_guessable_default_secret(self):
        old = os.environ.pop("AGENTWARDEN_SECRET", None)
        try:
            forger = Directory(secret="dev-secret")
            forger.add_role("r", allow=["*:*"])
            forger.add_agent("bot1", "x", ["r"])
            forged = forger.issue_token("bot1")
            victim = Directory()
            victim.add_role("r", allow=["*:*"])
            victim.add_agent("bot1", "alice", ["r"])
            self.assertEqual(victim.authorize(forged, "spend", "anything")[1], "bad signature")
            with tempfile.TemporaryDirectory() as tmp:
                p = os.path.join(tmp, "store.json")
                a, b = Directory(p), Directory(p)
                self.assertEqual(a.secret, b.secret, "store secret must persist across runs")
                self.assertNotEqual(a.secret, b"dev-secret")
        finally:
            if old is not None:
                os.environ["AGENTWARDEN_SECRET"] = old

    def test_malformed_tokens_are_rejected_cleanly(self):
        import base64

        h, _, _ = self.tok.split(".")
        junk_body = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        for bad in ("", "a.b", "a.b.c.d", f"{h}.{junk_body}.sig"):
            with self.subTest(bad=bad):
                self.assertFalse(self.d.authorize(bad, "read", "crm/a", now=1001)[0])
                with self.assertRaises(TokenError):
                    self.d.revoke(bad)
        self.assertEqual(self.d.revoked, set())

    def test_revoking_twice_or_after_disable_is_fine(self):
        self.d.revoke(self.tok)
        self.d.revoke(self.tok)
        self.d.disable_agent("bot1")
        self.d.revoke(self.tok)
        self.assertEqual(len(self.d.revoked), 1)

    def test_role_downgrade_takes_effect_on_existing_tokens(self):
        self.assertTrue(self.d.authorize(self.tok, "spend", "stripe/charge", amount=20, now=1001)[0])
        self.d.add_role("readonly", allow=["read:crm/*"])
        self.d.add_agent("bot1", "alice", ["readonly"])  # admin strips the spend role
        self.assertFalse(self.d.authorize(self.tok, "spend", "stripe/charge", amount=20, now=1001)[0])
        self.assertFalse(self.d.authorize(self.tok, "read", "crm/tickets/1", now=1001)[0], "token cannot gain roles")

    def test_token_lifetime_is_capped(self):
        for ttl in (0, -5, 10**8):
            with self.subTest(ttl=ttl), self.assertRaises(TokenError):
                self.d.issue_token("bot1", ttl=ttl)


if __name__ == "__main__":
    unittest.main()
