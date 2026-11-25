"""The Diagnostics page and the diag helper behind it.

note() always writes a tagged line into the app log, detail() only while
that area's switch is on (24 hours at most), every line loses IBANs, emails,
addresses and keys, Clear only hides lines (the file support needs stays
whole), and the page itself never shows a secret from the log or the
settings.
"""
import logging
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app import diag
from app.web import server

IBAN = "NL91ABNA0417164300"
EMAIL = "alex.doe@example.com"
ACTUAL_URL = "https://actual.alexdoe.example:5006"
SECRETS = (IBAN, "ABNA0417164300", "alex.doe", "example.com", "actual.alexdoe", "5006",
           "lic-SECRET-KEY", "hunter2")


def _reset_settings():
    with appdb._conn() as conn:
        appdb._ensure_tables(conn)
        conn.execute("DELETE FROM settings")
        conn.commit()
    diag.reset_cache()


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class DiagHelperTest(unittest.TestCase):
    def setUp(self):
        _reset_settings()
        self.capture = Capture()
        logging.getLogger("app.diag").addHandler(self.capture)

    def tearDown(self):
        logging.getLogger("app.diag").removeHandler(self.capture)

    def test_note_writes_a_tagged_line(self):
        diag.note("Sync", "Started (schedule)")
        self.assertEqual(len(self.capture.lines), 1)
        self.assertRegex(self.capture.lines[0], r"^\[diag\] \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ Sync: Started \(schedule\)$")

    def test_detail_only_while_switched_on(self):
        diag.detail("Bank", "GET /aspsps: HTTP 200")
        self.assertEqual(self.capture.lines, [])
        diag.set_detailed("Bank", True)
        diag.detail("Bank", "GET /aspsps: HTTP 200")
        self.assertTrue(any(l.endswith("Bank: GET /aspsps: HTTP 200") for l in self.capture.lines))
        # Other areas stay quiet.
        before = len(self.capture.lines)
        diag.detail("Email", "Login answer 235")
        self.assertEqual(len(self.capture.lines), before)

    def test_switch_turns_itself_off_after_24_hours(self):
        start = 1_800_000_000.0
        diag.set_detailed("Actual", True, now=start)
        self.assertTrue(diag.is_detailed("Actual", now=start + 23 * 3600))
        self.assertEqual(diag.detailed_until("Actual", now=start), start + 24 * 3600)
        self.assertFalse(diag.is_detailed("Actual", now=start + 24 * 3600))
        self.assertFalse(diag.is_detailed("Actual", now=start + 30 * 3600))

    def test_switch_is_kept_in_the_shared_settings(self):
        diag.set_detailed("Email", True)
        diag.reset_cache()      # as the scheduler or a restart would read it
        self.assertTrue(diag.is_detailed("Email"))
        diag.set_detailed("Email", False)
        diag.reset_cache()
        self.assertFalse(diag.is_detailed("Email"))

    def test_unknown_area_has_no_switch(self):
        with self.assertRaises(ValueError):
            diag.set_detailed("Error", True)

    def test_lines_never_carry_ibans_emails_or_addresses(self):
        diag.note("Email", f"Sent to {EMAIL} via smtp.example.com from {IBAN} at {ACTUAL_URL}/sync "
                           "and 192.168.1.20:5006")
        line = self.capture.lines[-1]
        for secret in (IBAN, "ABNA0417164300", "alex.doe", "actual.alexdoe", "192.168.1.20"):
            self.assertNotIn(secret, line)
        self.assertIn("[email]", line)
        self.assertIn("[address]", line)

    def test_line_is_one_line(self):
        diag.note("Sync", "first\nsecond\tthird")
        self.assertTrue(self.capture.lines[-1].endswith("Sync: first second third"))

    def test_note_never_raises(self):
        with patch.object(diag.logger, "info", side_effect=RuntimeError("disk full")):
            diag.note("Sync", "Started")

    def test_note_change_only_when_it_changes(self):
        diag.note_change("licence", "License", "Check: valid")
        diag.note_change("licence", "License", "Check: valid")
        diag.note_change("licence", "License", "Check: refused")
        self.assertEqual([l.split(": ", 1)[1] for l in self.capture.lines],
                         ["Check: valid", "Check: refused"])

    def test_parse_newest_first_and_hides_cleared(self):
        text = "\n".join([
            "2026-11-25 08:00:00,000 [INFO] [diag] 2026-11-25T08:00:00Z Sync: Started (schedule)",
            "2026-11-25 08:00:01,000 [INFO] app.sync: Fetched 9 transactions from Enable Banking",
            "2026-11-25 08:00:42,000 [INFO] [diag] 2026-11-25T08:00:42Z Sync: Done: 1 account, 9 new, 42 s",
            "2026-11-25 08:00:43,000 [INFO] [diag] 2026-11-25T08:00:43Z Error: Bank: ING HTTP 429",
        ])
        lines = diag.parse(text)
        self.assertEqual([l[1] for l in lines], ["Error", "Sync", "Sync"])
        self.assertEqual(lines[0][2], "Bank: ING HTTP 429")
        cleared = lines[1][0]
        self.assertEqual([l[2] for l in diag.parse(text, since=cleared)],
                         ["Bank: ING HTTP 429", "Done: 1 account, 9 new, 42 s"])

    def test_times_are_us_style_day_first(self):
        at = 1795075242   # 2026-11-19T08:00:42Z
        self.assertEqual(diag.format_time(at, "UTC"), "19 Nov 2026 8:00:42 AM")
        self.assertEqual(diag.format_time(at, "America/New_York"), "19 Nov 2026 3:00:42 AM")
        self.assertEqual(diag.format_when(at + 12 * 3600, "UTC", now=at), "8:00 PM")
        self.assertEqual(diag.format_when(at + 24 * 3600, "UTC", now=at), "8:00 AM tomorrow")
        self.assertEqual(diag.clock_text("20:00"), "8:00 PM")
        self.assertEqual(diag.clock_text("00:30"), "12:30 AM")


class DiagLinesFromTheAppTest(unittest.TestCase):
    """The lines the sync, bank and email code write: counts and codes only."""
    def setUp(self):
        _reset_settings()
        self.capture = Capture()
        logging.getLogger("app.diag").addHandler(self.capture)

    def tearDown(self):
        logging.getLogger("app.diag").removeHandler(self.capture)

    def test_sync_done_line_and_last_sync_summary(self):
        from app import sync

        def fake_run(only_account_id=None):
            sync._count("accounts", 3)
            sync._count("new", 14)
            sync._count("by_hand", 2)
            return True, 14, "OK"

        with patch.object(sync, "_run", side_effect=fake_run):
            sync.run(trigger="schedule")
        self.assertTrue(self.capture.lines[0].endswith("Sync: Started (schedule)"))
        self.assertRegex(self.capture.lines[-1],
                         r"Sync: Done: 3 accounts, 14 new, 2 matched to ones added by hand, \d+ s$")
        import json
        last = json.loads(appdb.get_setting("diag_last_sync"))
        self.assertEqual((last["ok"], last["accounts"], last["new"]), (True, 3, 14))

    def test_sync_crash_is_an_error_line(self):
        from app import sync
        with patch.object(sync, "_run", side_effect=KeyError("x")):
            with self.assertRaises(KeyError):
                sync.run(trigger="schedule")
        self.assertIn("Error: Sync: Stopped by an unexpected error (KeyError)", self.capture.lines[-1])

    def test_bank_problem_names_the_code_not_the_url(self):
        import requests
        from app import sync
        response = requests.Response()
        response.status_code = 429
        response.url = "https://api.enablebanking.com/accounts/uid-123/transactions"
        err = requests.HTTPError("429 for url " + response.url, response=response)
        self.assertEqual(sync._bank_problem("Revolut", err), "Revolut HTTP 429, will try again at the next sync")
        self.assertEqual(sync._error_kind(requests.ConnectionError("to " + ACTUAL_URL)), "ConnectionError")

    def test_email_failure_line_has_no_host_or_address(self):
        import smtplib
        from app import email_notify
        with patch.object(email_notify.config, "NOTIFY_EMAIL", EMAIL), \
             patch.object(email_notify.config, "SMTP_USER", EMAIL), \
             patch.object(email_notify.config, "SMTP_PASSWORD", "hunter2"), \
             patch.object(email_notify.config, "SMTP_HOST", "smtp.example.com", create=True), \
             patch.object(email_notify, "_smtp_host", return_value="smtp.example.com"), \
             patch.object(email_notify, "_is_unsubscribed", return_value=False), \
             patch.object(email_notify.smtplib, "SMTP",
                          side_effect=smtplib.SMTPAuthenticationError(535, b"bad login for alex.doe@example.com")):
            email_notify.send("Bridge Bank: sync failed", "body")
        line = self.capture.lines[-1]
        self.assertIn("Error: Email: Not sent (sync failed): SMTPAuthenticationError, SMTP 535", line)
        for secret in ("example.com", "alex.doe", "hunter2"):
            self.assertNotIn(secret, line)


class FactsTest(unittest.TestCase):
    """The facts that reach outside: never the Actual address."""
    def _actual(self, **get):
        from unittest.mock import MagicMock
        with patch.object(server.config, "ACTUAL_URL", ACTUAL_URL), \
             patch("requests.get", **get) as fake:
            text = server._fact_actual()
        self.assertNotIn("alexdoe", text)
        self.assertNotIn("5006", text)
        return text, fake

    def test_actual_reachable(self):
        from unittest.mock import MagicMock
        answer = MagicMock(status_code=200)
        answer.json.return_value = {"build": {"version": "26.3.0"}}
        text, fake = self._actual(return_value=answer)
        self.assertTrue(text.startswith("Reachable, Actual 26.3.0, actualpy "))
        self.assertEqual(fake.call_args.args[0], ACTUAL_URL + "/info")

    def test_actual_answers_with_an_error(self):
        from unittest.mock import MagicMock
        text, _ = self._actual(return_value=MagicMock(status_code=502))
        self.assertTrue(text.startswith("Not reachable (HTTP 502), actualpy "))

    def test_actual_not_reachable(self):
        import requests
        text, _ = self._actual(side_effect=requests.ConnectionError(f"Max retries for {ACTUAL_URL}/info"))
        self.assertTrue(text.startswith("Not reachable (ConnectionError), actualpy "))

    def test_memory_from_proc(self):
        from unittest.mock import mock_open
        with patch("builtins.open", mock_open(read_data="Name:\tpython\nVmRSS:\t  120832 kB\n")):
            self.assertEqual(server._memory_now(), "118 MB")

    def test_stopped_sync_uses_fixed_words(self):
        from app import sync
        capture = Capture()
        logging.getLogger("app.diag").addHandler(capture)
        try:
            with patch.object(sync, "_run", return_value=(False, 0, "License invalid: key lic-SECRET-KEY expired")):
                sync.run(trigger="schedule")
        finally:
            logging.getLogger("app.diag").removeHandler(capture)
        self.assertRegex(capture.lines[-1], r"Sync: Stopped: the license check failed, \d+ s$")
        self.assertNotIn("lic-SECRET-KEY", appdb.get_setting("diag_last_sync"))


class DiagnosticsPageTest(unittest.TestCase):
    def setUp(self):
        _reset_settings()
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "bridge-bank.log")
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(self.log, "w") as f:
            # An older line with an address, an IBAN and an email, as earlier
            # versions logged them, then the page's own lines.
            f.write(f"2026-11-01 07:00:00,000 [ERROR] app.sync: Could not connect to Actual Budget at "
                    f"{ACTUAL_URL}. IBAN {IBAN}, mail {EMAIL}\n")
            f.write(f"2026-11-25 08:00:00,000 [INFO] [diag] {now} Sync: Started (schedule)\n")
            f.write(f"2026-11-25 08:00:01,000 [INFO] [diag] {now} Error: Bank: ING HTTP 429\n")
        self.client = server.app.test_client()
        self.patches = [
            patch.object(server, "LOG_FILE", self.log),
            patch.object(server.config, "LICENCE_KEY", "lic-SECRET-KEY"),
            patch.object(server.config, "ACTUAL_URL", ACTUAL_URL),
            patch.object(server.config, "ACTUAL_PASSWORD", "hunter2"),
            patch.object(server.config, "NOTIFY_EMAIL", EMAIL),
            patch.object(server.config, "TIMEZONE", "Europe/Lisbon"),
            patch.object(server.licence, "get_activation_info",
                         return_value={"usage": 1, "limit": 2, "is_trial": False}),
            patch.object(server, "_fact_actual", return_value="Reachable, Actual 26.3.0, actualpy 0.23.0"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def assertNoSecrets(self, text):
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def test_page_renders_with_switches(self):
        response = self.client.get("/diagnostics")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        for words in ("About this Bridge Bank", "Detailed log", "Bank connection", "Writing to Actual Budget",
                      "License and updates", "Copy log", "Download log", "Kept on your server only"):
            self.assertIn(words, page)
        self.assertIn('href="/diagnostics" class="active"', page)
        self.assertNoSecrets(page)

    def test_page_needs_no_setup(self):
        with patch.object(server.config, "is_configured", return_value=False):
            self.assertEqual(self.client.get("/diagnostics").status_code, 200)

    def test_api_shows_diag_lines_and_facts_without_secrets(self):
        response = self.client.get("/api/diagnostics")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertNoSecrets(response.get_data(as_text=True))
        self.assertEqual({l[1] for l in data["lines"]}, {"Sync", "Error"})
        self.assertRegex(data["lines"][0][0], r"^\d{1,2} [A-Z][a-z]{2} \d{4} \d{1,2}:\d\d:\d\d [AP]M$")
        facts = dict(data["facts"])
        self.assertEqual(facts["License"], "Not checked yet, 1 of 2 machines")
        self.assertEqual(facts["Bank accounts"], "None connected")
        self.assertIn("Memory now", facts)

    def test_clear_hides_lines_but_keeps_the_file(self):
        with open(self.log, "rb") as f:
            before = f.read()
        self.assertEqual(self.client.post("/api/diagnostics/clear").status_code, 200)
        self.assertEqual(self.client.get("/api/diagnostics").get_json()["lines"], [])
        with open(self.log, "rb") as f:
            self.assertEqual(f.read(), before)
        # Download log still has everything, redacted.
        logs = self.client.get("/api/logs?lines=50").get_json()["logs"]
        self.assertIn("Started (schedule)", logs)
        self.assertNotIn(IBAN, logs)

    def test_switch_endpoint(self):
        response = self.client.post("/api/diagnostics/detailed", json={"area": "Bank", "on": True})
        self.assertEqual(response.status_code, 200)
        bank = next(s for s in response.get_json()["switches"] if s["area"] == "Bank")
        self.assertTrue(bank["on"])
        self.assertTrue(bank["until"].startswith("On until "))
        self.assertTrue(diag.is_detailed("Bank"))
        self.client.post("/api/diagnostics/detailed", json={"area": "Bank", "on": False})
        self.assertFalse(diag.is_detailed("Bank"))
        self.assertEqual(self.client.post("/api/diagnostics/detailed",
                                          json={"area": "Error", "on": True}).status_code, 400)

    def test_a_failing_fact_does_not_break_the_page(self):
        with patch.object(server.licence, "get_activation_info", side_effect=RuntimeError("down")):
            facts = dict(self.client.get("/api/diagnostics").get_json()["facts"])
        self.assertEqual(facts["License"], "Unknown")

    def test_status_links_to_diagnostics(self):
        with patch.object(server.config, "is_configured", return_value=True), \
             patch.object(server.config, "is_connected", return_value=True), \
             patch.object(server.licence, "validate", return_value={"valid": True}), \
             patch.object(server, "_get_bank_seat_error", return_value=(None, None)), \
             patch.object(server, "_get_days_left", return_value=None):
            page = self.client.get("/status").get_data(as_text=True)
        self.assertIn('<a class="btn" href="/diagnostics">Diagnostics</a>', page)
        self.assertNotIn("Download logs", page)


if __name__ == "__main__":
    unittest.main()
