"""The Status page: one line per account, 30 days of squares, the headline and the schedule."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app.web import server

ACT_INFO = {"usage": 1, "limit": 2, "is_trial": False}


def _utc(minutes_ago):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%d %H:%M:%S")


class StatusPageTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
            for t in ("settings", "sync_log", "bank_accounts"):
                conn.execute(f"DELETE FROM {t}")
            conn.execute("INSERT INTO settings (key, value) VALUES ('budget_notice_dismissed', '1')")
            conn.commit()
        expiry = (datetime.now(timezone.utc) + timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        appdb.add_bank_account("s1", "u1", "Revolut", "PT", "Personal", session_expiry=expiry)
        appdb.add_bank_account("s2", "u2", "N26", "PT", "N26", session_expiry=expiry)
        appdb.add_bank_account("s3", "u3", "eToro", "", "E-Toro", provider="etoro", sync_mode="balance")
        self.client = server.app.test_client()
        self.patches = [
            patch.object(server.config, "is_configured", return_value=True),
            patch.object(server.config, "is_connected", return_value=True),
            patch.object(server.config, "TIMEZONE", "Europe/Lisbon"),
            patch.object(server.config, "SYNC_FREQUENCY", "6"),
            patch.object(server.config, "SYNC_TIME", "03:00"),
            patch.object(server.licence, "validate", return_value={"valid": True}),
            patch.object(server.licence, "get_activation_info", return_value=ACT_INFO),
            patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 3, "limit": 5})),
            patch.object(server, "_get_days_left", return_value=None),
            patch.object(server, "_start_iban_lookup", return_value=None),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def log(self, minutes_ago, status, tx, message):
        with appdb._conn() as conn:
            conn.execute("INSERT INTO sync_log (ran_at, status, tx_count, message) VALUES (?, ?, ?, ?)",
                         (_utc(minutes_ago), status, tx, message))
            conn.commit()

    def overview(self):
        return server._status_overview(appdb.get_all_bank_accounts(), server._local_zone())

    def page(self):
        r = self.client.get("/status")
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)

    def test_no_syncs_yet(self):
        ov = self.overview()
        self.assertEqual(ov["state"], "none")
        self.assertTrue(all(l["last"] is None for l in ov["lanes"]))
        self.assertIn("No syncs yet.", self.page())

    def test_all_accounts_ok(self):
        self.log(3, "success", 2, "Revolut (PT) → Personal")
        self.log(3, "success", 0, "N26 (PT) → N26")
        self.log(3, "success", 1, "eToro → E-Toro")
        ov = self.overview()
        self.assertEqual(ov["state"], "ok")
        self.assertEqual([l["last"]["tx"] for l in ov["lanes"]], [2, 0, 1])
        self.assertEqual(ov["lanes"][0]["cells"][-1]["level"], 2)
        self.assertTrue(ov["lanes"][0]["cells"][-1]["today"])
        self.assertEqual(ov["tx_30"], 3)
        body = self.page()
        self.assertIn("Everything synced", body)
        self.assertIn("All 3 accounts synced without a problem.", body)

    def test_one_account_failed(self):
        self.log(60, "success", 1, "N26 (PT) → N26")
        self.log(3, "success", 2, "Revolut (PT) → Personal")
        self.log(3, "failure", 0, "N26 (PT) → N26: Your bank is rate-limiting requests.")
        self.log(3, "success", 1, "eToro → E-Toro")
        ov = self.overview()
        self.assertEqual(ov["state"], "partial")
        self.assertEqual([l["dest"] for l in ov["failed"]], ["N26"])
        n26 = ov["lanes"][1]
        self.assertFalse(n26["last"]["ok"])
        self.assertTrue(n26["cells"][-1]["fail"])
        self.assertEqual(n26["total"], 1)
        body = self.page()
        self.assertIn("1 of 3 accounts didn't sync", body)
        self.assertIn("Your bank is rate-limiting requests.", body)

    def test_failure_without_an_account_stops_every_line(self):
        self.log(60, "success", 1, "Revolut (PT) → Personal")
        self.log(2, "failure", 0, "License invalid: deactivated")
        ov = self.overview()
        self.assertEqual(ov["state"], "fail")
        self.assertTrue(all(not l["last"]["ok"] for l in ov["lanes"]))

    def test_rows_of_a_removed_account_are_ignored(self):
        self.log(5, "success", 4, "ING (NL) → Old")
        self.log(4, "failure", 0, "ING (NL) → Old: gone")
        ov = self.overview()
        self.assertEqual(ov["state"], "none")
        self.assertEqual(ov["tx_30"], 0)

    def test_expiry_levels(self):
        now = server._now_local(server._local_zone())
        soon = {"session_expiry": (datetime.now(timezone.utc) + timedelta(days=5, hours=1)).isoformat()}
        gone = {"session_expiry": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}
        self.assertEqual(server._auth_info(soon, now)["level"], "warn")
        self.assertEqual(server._auth_info(soon, now)["text"], "5 days left")
        self.assertEqual(server._auth_info(gone, now)["level"], "bad")
        self.assertEqual(server._auth_info({"sync_mode": "balance", "provider": "etoro"}, now)["note"], "API key")

    def test_schedule(self):
        info = server._schedule_info(server._local_zone())
        self.assertEqual(info["times"], ["03:00", "09:00", "15:00", "21:00"])
        self.assertIn(info["next"], info["times"])
        with patch.object(server.config, "SYNC_FREQUENCY", "0"):
            self.assertIsNone(server._schedule_info(server._local_zone()))

    def test_log_page_groups_runs(self):
        self.log(400, "success", 1, "Revolut (PT) → Personal")
        self.log(3, "success", 2, "Revolut (PT) → Personal")
        self.log(3, "failure", 0, "N26 (PT) → N26: Your bank is rate-limiting requests.")
        entries = server._log_page_entries(appdb.get_sync_log_page(1, 10)["syncs"], server._local_zone())
        heads = [e for e in entries if "head" in e]
        self.assertEqual(len(heads), 2)
        fail = [e for e in entries if "head" not in e and not e["ok"]][0]
        self.assertEqual(fail["label"], "N26 (PT) → N26")
        self.assertEqual(fail["detail"], "Your bank is rate-limiting requests.")

    def test_day_first_dates(self):
        self.assertEqual(server._day_first("2026-11-04T10:00:00"), "4 Nov 2026")
        self.assertEqual(server._day_first(None), "")


if __name__ == "__main__":
    unittest.main()
