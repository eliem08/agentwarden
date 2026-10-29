"""Billing shape tests: monthly checkout carries the 14-day trial, and /pricing says so."""

import http.client
import pathlib
import tempfile
import threading
import unittest
import urllib.request

from agentwarden import web


class TestBillingShape(unittest.TestCase):
    def _server(self, t):
        env = {
            "STRIPE_SECRET_KEY": "sk_test_x",
            "STRIPE_WEBHOOK_SECRET": "whsec_test",
            "STRIPE_PRICES": "team=price_123,business=price_456,enterprise=price_789",
            "PUBLIC_URL": "https://example.test",
        }
        srv = web.make_server("127.0.0.1", 0, pathlib.Path(t), env=env)
        billing = srv.RequestHandlerClass.billing
        sent = {}
        billing._stripe = lambda path, form: sent.update(form) or {"url": "https://checkout.test/s"}
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, sent

    def test_monthly_checkout_carries_14_day_trial(self):
        with tempfile.TemporaryDirectory() as t:
            srv, sent = self._server(t)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
                conn.request("POST", "/billing/checkout", "plan=business")
                res = conn.getresponse()
                self.assertEqual((res.status, res.getheader("Location")), (303, "https://checkout.test/s"))
                conn.close()
            finally:
                srv.shutdown()
            self.assertEqual(sent["mode"], "subscription")
            self.assertEqual(sent["line_items[0][price]"], "price_456")
            self.assertEqual(sent["subscription_data[trial_period_days]"], "14")

    def test_pricing_page_notes_trial(self):
        with tempfile.TemporaryDirectory() as t:
            srv, _ = self._server(t)
            try:
                body = urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/pricing", timeout=30).read()
            finally:
                srv.shutdown()
            self.assertIn(b"14-day free trial", body)


if __name__ == "__main__":
    unittest.main()
