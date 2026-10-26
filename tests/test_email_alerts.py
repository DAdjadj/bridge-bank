"""The alert emails: every one renders as HTML and plain text, and is sent as both.

The HTML is Bridge Bank's blueprint look from the licence emails. These tests
build each alert from sample sync results, check what the reader sees in both
parts, and check that sending still goes through the same SMTP path with the
unsubscribe check in front of it.
"""
import datetime
import email
import re
import unittest
from unittest.mock import MagicMock, patch

from app import config, email_design, email_notify

NOW = datetime.datetime(2026, 10, 26, 7, 0, tzinfo=datetime.timezone.utc)

SUCCESSES = ["ING (NL) → Joint checking: 7 transactions", "Revolut (PT) → Revolut: 5 transactions",
             "Wise (BE) → Wise EUR: 0 transactions", "Internal transfers: 2 linked"]
ERRORS = ["Wise (BE) → Wise EUR: Could not connect to Actual Budget at http://actual:5006. Error: timed out"]

SETTINGS = dict(NOTIFY_EMAIL="alex@example.com", SMTP_USER="alex@icloud.com", SMTP_PASSWORD="pw", SMTP_HOST="",
                SMTP_PORT="587", SMTP_FROM="", SMTP_SECURITY="starttls", SMTP_AUTH="true", SMTP_TLS_VERIFY="true",
                NOTIFY_ON="all", BRIDGE_BANK_URL="http://192.168.1.20:3002", TIMEZONE="")

# Pictographs and the tick/cross marks the old plain-text alerts used.
EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿⬀-⯿]")


def every_alert():
    return {
        "success": email_notify.build_success(12, SUCCESSES),
        "success-none": email_notify.build_success(0, ["ING (NL) → Joint checking: 0 transactions"]),
        "partial": email_notify.build_partial(SUCCESSES[:2], ERRORS),
        "failure-accounts": email_notify.build_failure("\n".join(f"  ✗ {e}" for e in ERRORS + [
            "No active bank session for ING. Open Bridge Bank and click 'Re-authorise bank' on the Bank page."])),
        "failure-single": email_notify.build_failure("License invalid: This licence key has been deactivated."),
        "trial-warning": email_notify.build_trial_expiry_warning(3),
        "trial-expired": email_notify.build_trial_expired(),
        "session": email_notify.build_session_expiry_warning(3, "ING"),
        "test": email_notify.build_test(),
    }


class AlertContentTest(unittest.TestCase):
    def setUp(self):
        patches = [patch.object(config, k, v) for k, v in SETTINGS.items()]
        patches.append(patch.object(email_notify, "_now", return_value=NOW))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_every_alert_renders_in_the_blueprint_look(self):
        for name, (subject, e) in every_alert().items():
            with self.subTest(name):
                html, text = email_design.render_html(e), email_design.render_text(e)
                self.assertTrue(subject.startswith("Bridge Bank: "))
                self.assertIn("bb-grid.png", html)
                self.assertIn("bb-bridge.png", html)
                self.assertIn("prefers-color-scheme:dark", html)
                self.assertIn(e["title"], text)
                for part in (subject, html, text):
                    self.assertNotIn("—", part)
                    self.assertNotIn("–", part)
                    self.assertIsNone(EMOJI.search(part), name)

    def test_images_come_from_the_licence_server(self):
        _, e = email_notify.build_success(1, SUCCESSES[:1])
        srcs = re.findall(r'src="([^"]+)"', email_design.render_html(e))
        self.assertTrue(srcs)
        for src in srcs:
            self.assertTrue(src.startswith("https://api.bridgebank.app/static/email/"), src)

    def test_success_lists_each_account_and_the_transfers(self):
        _, e = email_notify.build_success(12, SUCCESSES)
        self.assertEqual(e["intro"][0], "Every account synced, and 12 new transactions are in Actual Budget.")
        self.assertIn({"label": "Accounts", "value": "3 of 3 synced"}, e["facts"])
        self.assertEqual([(a["name"], a["result"]) for a in e["accounts"]], [
            ("ING (NL) → Joint checking", "7 new"), ("Revolut (PT) → Revolut", "5 new"),
            ("Wise (BE) → Wise EUR", "0 new"), ("Internal transfers", "2 linked")])
        text = email_design.render_text(e)
        self.assertIn("Imported: 12 transactions", text)
        self.assertIn("- ING (NL) → Joint checking: 7 new", text)
        self.assertIn("Open Bridge Bank: http://192.168.1.20:3002", text)

    def test_success_with_nothing_new(self):
        _, e = email_notify.build_success(0, ["ING (NL) → Joint checking: 0 transactions"])
        self.assertEqual(e["intro"][0], "Your account synced. There were no new transactions this time.")

    def test_partial_puts_the_failed_account_first_with_its_error(self):
        subject, e = email_notify.build_partial(SUCCESSES[:2], ERRORS)
        self.assertEqual(subject, "Bridge Bank: sync partially complete")
        self.assertEqual(e["title"], "One account didn't sync")
        self.assertIn({"label": "Imported", "value": "12 transactions"}, e["facts"])
        self.assertIn({"label": "Accounts", "value": "2 of 3 synced"}, e["facts"])
        first = e["accounts"][0]
        self.assertEqual((first["name"], first["result"], first["ok"]), ("Wise (BE) → Wise EUR", "Failed", False))
        # The error keeps its own colons: the split is after the account label only.
        self.assertEqual(first["detail"], "Could not connect to Actual Budget at http://actual:5006. Error: timed out")

    def test_failure_with_account_errors(self):
        subject, e = email_notify.build_failure("  ✗ " + ERRORS[0] + "\n  ✗ No active bank session for ING. Re-authorise.")
        self.assertEqual(subject, "Bridge Bank: sync failed")
        self.assertIn({"label": "Accounts", "value": "0 of 2 synced", "bad": True}, e["facts"])
        unnamed = [a for a in e["accounts"] if not a["name"]]
        self.assertEqual(unnamed[0]["detail"], "No active bank session for ING. Re-authorise.")
        self.assertNotIn("✗", email_design.render_text(e))

    def test_failure_with_one_message(self):
        _, e = email_notify.build_failure("Unexpected error during scheduled sync: boom")
        self.assertEqual(e["facts"][0]["label"], "Error")
        self.assertEqual(e["facts"][0]["value"], "Unexpected error during scheduled sync: boom")
        self.assertFalse(e.get("accounts"))

    def test_trial_and_session_dates(self):
        subject, e = email_notify.build_trial_expiry_warning(3)
        self.assertEqual(subject, "Bridge Bank: trial expires in 3 days")
        self.assertIn({"label": "Ends", "value": "Thursday 29 October", "wide": True}, e["facts"])
        subject, e = email_notify.build_trial_expiry_warning(1)
        self.assertEqual(subject, "Bridge Bank: trial expires in 1 day")
        self.assertEqual(e["title"], "Your trial ends tomorrow")
        subject, e = email_notify.build_session_expiry_warning(3, "ING")
        self.assertEqual(subject, "Bridge Bank: bank session expires in 3 days")
        self.assertEqual(e["title"], "Your ING connection expires in 3 days")
        self.assertEqual(e["cta"]["href"], "http://192.168.1.20:3002/bank")
        subject, e = email_notify.build_session_expiry_warning(0)
        self.assertEqual(subject, "Bridge Bank: bank session expires today")
        self.assertEqual(e["title"], "Your bank connection expires today")

    def test_without_an_app_address_there_is_no_button(self):
        with patch.object(config, "BRIDGE_BANK_URL", ""):
            _, e = email_notify.build_success(1, SUCCESSES[:1])
            html = email_design.render_html(e)
        self.assertNotIn("Open Bridge Bank</span>", html)
        self.assertIn("Notifications page.", email_design.render_text(e))

    def test_test_email_shows_the_settings(self):
        _, e = email_notify.build_test("errors")
        facts = {f["label"]: f["value"] for f in e["facts"]}
        self.assertEqual(facts, {"Sent to": "alex@example.com", "When to notify": "Errors only", "Sent through": "smtp.mail.me.com"})

    def test_names_from_the_bank_are_escaped(self):
        _, e = email_notify.build_success(1, ["<b>Evil</b> & Co → Main: 1 transaction"])
        html = email_design.render_html(e)
        self.assertNotIn("<b>Evil</b>", html)
        self.assertIn("&lt;b&gt;Evil&lt;/b&gt; &amp; Co", html)


class SendingTest(unittest.TestCase):
    def setUp(self):
        patches = [patch.object(config, k, v) for k, v in SETTINGS.items()]
        patches.append(patch.object(email_notify, "_now", return_value=NOW))
        patches.append(patch.object(email_notify, "_is_unsubscribed", return_value=False))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.smtp = MagicMock()
        p = patch.object(email_notify.smtplib, "SMTP", return_value=self.smtp)
        self.SMTP = p.start()
        self.addCleanup(p.stop)

    def sent(self):
        conn = self.smtp.__enter__.return_value
        conn.sendmail.assert_called_once()
        sender, to, raw = conn.sendmail.call_args.args
        return sender, to, email.message_from_string(raw), conn

    def test_alerts_go_out_as_text_and_html(self):
        email_notify.send_success(12, SUCCESSES)
        self.SMTP.assert_called_once_with("smtp.mail.me.com", 587)
        sender, to, msg, conn = self.sent()
        conn.starttls.assert_called_once()
        conn.login.assert_called_once_with("alex@icloud.com", "pw")
        self.assertEqual((sender, to), ("alex@icloud.com", "alex@example.com"))
        self.assertEqual(msg["Subject"], "Bridge Bank: sync complete")
        self.assertEqual(msg.get_content_type(), "multipart/alternative")
        plain, html = msg.get_payload()
        self.assertEqual(plain.get_content_type(), "text/plain")
        self.assertEqual(html.get_content_type(), "text/html")
        self.assertIn("Imported: 12 transactions", plain.get_payload(decode=True).decode("utf-8"))
        self.assertIn("bb-bridge.png", html.get_payload(decode=True).decode("utf-8"))

    def test_plain_send_stays_plain_text(self):
        email_notify.send("Bridge Bank: hello", "Just text.")
        _, _, msg, _ = self.sent()
        self.assertEqual(msg.get_content_type(), "text/plain")
        self.assertEqual(msg.get_payload(), "Just text.")

    def test_notify_on_is_respected(self):
        with patch.object(config, "NOTIFY_ON", "errors"):
            email_notify.send_success(3, SUCCESSES[:1])
            self.smtp.__enter__.return_value.sendmail.assert_not_called()
            email_notify.send_partial(SUCCESSES[:1], ERRORS)
        self.assertEqual(self.sent()[2]["Subject"], "Bridge Bank: sync partially complete")
        with patch.object(config, "NOTIFY_ON", "never"):
            self.smtp.reset_mock()
            email_notify.send_failure("boom")
            self.smtp.__enter__.return_value.sendmail.assert_not_called()

    def test_unsubscribed_address_gets_nothing(self):
        with patch.object(email_notify, "_is_unsubscribed", return_value=True):
            email_notify.send_trial_expired()
        self.SMTP.assert_not_called()

    def test_test_button_raises_a_readable_error(self):
        self.smtp.__enter__.return_value.login.side_effect = Exception("535 authentication failed")
        with self.assertRaises(RuntimeError) as ctx:
            email_notify.send_test()
        self.assertIn("Wrong password", str(ctx.exception))


class TestButtonTest(unittest.TestCase):
    """The Notifications page's test button sends the new test email, with the choice on screen."""

    def test_posts_the_unsaved_choice(self):
        import tempfile
        from app import db as appdb
        appdb.DB_PATH = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        from app.web import server
        client = server.app.test_client()
        with patch.object(server.config, "set"), \
             patch.object(server.config, "is_configured", return_value=True), \
             patch.object(email_notify, "send_test") as send_test:
            response = client.post("/email/test", json={"notify_email": "alex@example.com", "notify_on": "errors"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        send_test.assert_called_once_with("errors")


if __name__ == "__main__":
    unittest.main()
