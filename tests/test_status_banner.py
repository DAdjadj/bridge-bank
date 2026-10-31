"""The Status page banner and the sidebar dot follow the last sync."""
import tempfile
import unittest
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app.web import server

ACT_INFO = {"usage": 1, "limit": 2, "is_trial": False}


class StatusBannerTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
            conn.execute("DELETE FROM settings")
            conn.execute("DELETE FROM sync_log")
            conn.execute("INSERT INTO settings (key, value) VALUES ('budget_notice_dismissed', '1')")
            conn.commit()
        self.client = server.app.test_client()
        self.patches = [
            patch.object(server.config, "is_configured", return_value=True),
            patch.object(server.config, "is_connected", return_value=True),
            patch.object(server.licence, "validate", return_value={"valid": True}),
            patch.object(server.licence, "get_activation_info", return_value=ACT_INFO),
            patch.object(server, "_get_bank_seat_error", return_value=(None, None)),
            patch.object(server, "_get_days_left", return_value=None),
            patch.object(server, "_start_iban_lookup", return_value=None),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def page(self):
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_not_synced_yet(self):
        body = self.page()
        self.assertIn("Not synced yet", body)
        self.assertNotIn("health-dot", body)

    def test_all_synced(self):
        appdb.log_sync("success", tx_count=3, message="Revolut (PT) → Personal")
        body = self.page()
        self.assertIn("All synced", body)
        self.assertIn('class="health-dot "', body)
        self.assertIn("3 transactions", body)

    def test_needs_attention(self):
        appdb.log_sync("success", tx_count=1, message="Revolut (PT) → Personal")
        appdb.log_sync("failure", message="N26 (PT) → N26: Your bank is rate-limiting requests.")
        body = self.page()
        self.assertIn("Needs attention", body)
        self.assertIn('class="health-dot bad"', body)
        self.assertIn("Your bank is rate-limiting requests.", body)


if __name__ == "__main__":
    unittest.main()
