"""The one-time Bridge Budget note on the status page.

It shows until it is dismissed (the close button, "Don't show again" or
opening the link all post to /budget-notice/dismiss), then never again.
"""
import tempfile
import unittest
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app.web import server

ACT_INFO = {"usage": 1, "limit": 2, "is_trial": False}


class BudgetNoticeTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
            conn.execute("DELETE FROM settings")
            conn.commit()
        self.client = server.app.test_client()
        self.patches = [
            patch.object(server.config, "is_configured", return_value=True),
            patch.object(server.config, "is_connected", return_value=True),
            patch.object(server.licence, "validate", return_value={"valid": True}),
            patch.object(server.licence, "get_activation_info", return_value=ACT_INFO),
            patch.object(server, "_get_bank_seat_error", return_value=(None, None)),
            patch.object(server, "_get_days_left", return_value=None),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def status_page(self):
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_shows_until_dismissed(self):
        self.assertIn("Bridge Budget is here", self.status_page())
        self.assertIn("https://bridgebank.app/budget?ref=bridge-bank-app", self.status_page())

        response = self.client.post("/budget-notice/dismiss")
        self.assertEqual(response.status_code, 204)

        self.assertNotIn("Bridge Budget is here", self.status_page())
        self.assertEqual(appdb.get_setting("budget_notice_dismissed"), "1")


if __name__ == "__main__":
    unittest.main()
