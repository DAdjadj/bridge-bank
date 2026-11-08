"""The setup pages keep what's saved when a form brings something wrong.

- Enable Banking: a file that isn't a private key is refused, and the key
  already saved stays.
- Notifications: picking no SMTP security and then TLS again keeps
  certificate checks on.
- Send test email: the saved SMTP password is never sent to a different
  server than the one it was saved for.
- Sync schedule: a time or frequency that can't be read is refused, so it
  can't stop the scheduler.
"""
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

from app import config
from app import db as appdb

CONFIG_KEYS = [k for k in dir(config) if k.isupper() and not k.startswith("_")]
GOOD_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"


@unittest.skipUnless(HAVE_FLASK, "needs flask")
class SetupFormsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        appdb.DB_PATH = os.path.join(self._tmp.name, "instance.db")
        saved = {k: getattr(config, k) for k in CONFIG_KEYS}
        self.addCleanup(lambda: [setattr(config, k, v) for k, v in saved.items()])
        p = patch.object(config, "CONFIG_FILE", os.path.join(self._tmp.name, "config.json"))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)
        p = patch.object(config, "is_configured", return_value=False)  # no scheduler threads
        p.start()
        self.addCleanup(p.stop)
        from app.web import server
        self.server = server
        self.client = server.app.test_client()

    def saved(self):
        with open(config.CONFIG_FILE) as f:
            return json.load(f)

    # Enable Banking key

    def test_a_file_that_is_not_a_key_keeps_the_saved_key(self):
        appdb.set_setting("eb_pem_content", GOOD_PEM)
        config.set("EB_APPLICATION_ID", "app-old")
        r = self.client.post("/setup/bank", data={
            "eb_app_id": "app-new", "pem_file": (io.BytesIO(b"just some notes"), "notes.txt")},
            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertIn("valid .pem", r.get_data(as_text=True))
        self.assertEqual(appdb.get_setting("eb_pem_content"), GOOD_PEM)
        self.assertEqual(config.EB_APPLICATION_ID, "app-old")

    def test_an_empty_upload_is_refused(self):
        appdb.set_setting("eb_pem_content", GOOD_PEM)
        r = self.client.post("/setup/bank", data={
            "eb_app_id": "app-1", "pem_file": (io.BytesIO(b""), "private.pem")},
            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(appdb.get_setting("eb_pem_content"), GOOD_PEM)

    def test_a_real_key_is_saved(self):
        r = self.client.post("/setup/bank", data={
            "eb_app_id": "app-1", "pem_file": (io.BytesIO(GOOD_PEM.encode()), "private.pem")},
            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(appdb.get_setting("eb_pem_content"), GOOD_PEM.strip())

    def test_saving_without_a_new_file_keeps_the_key(self):
        appdb.set_setting("eb_pem_content", GOOD_PEM)
        r = self.client.post("/setup/bank", data={"eb_app_id": "app-2"}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(appdb.get_setting("eb_pem_content"), GOOD_PEM)
        self.assertEqual(config.EB_APPLICATION_ID, "app-2")

    # SMTP certificate checks

    def _notifications(self, security, verify):
        form = {"notify_email": "alex@example.com", "smtp_user": "alex@icloud.com", "smtp_password": "pw",
                "smtp_security": security, "smtp_auth": "true", "notify_on": "all"}
        if verify:
            form["smtp_tls_verify"] = "on"
        return self.client.post("/setup/notifications", data=form)

    def test_no_security_and_back_keeps_certificate_checks_on(self):
        self._notifications("starttls", True)
        # the browser doesn't send the greyed-out box when security is None
        self._notifications("none", False)
        self.assertEqual(config.SMTP_TLS_VERIFY, "true")
        page = self.client.get("/setup/notifications").get_data(as_text=True)
        self.assertRegex(page, r'name="smtp_tls_verify"\s+checked')
        self._notifications("starttls", True)
        self.assertEqual(config.SMTP_TLS_VERIFY, "true")

    def test_turning_checks_off_with_tls_still_works(self):
        self._notifications("ssl", False)
        self.assertEqual(config.SMTP_TLS_VERIFY, "false")

    # Send test email

    def _saved_smtp(self):
        for k, v in dict(SMTP_USER="alex@example.org", SMTP_PASSWORD="saved-pw", SMTP_HOST="mail.example.org",
                         SMTP_AUTH="true", SMTP_SECURITY="starttls", NOTIFY_EMAIL="alex@example.org").items():
            config.set(k, v)

    def test_saved_password_is_not_sent_to_a_new_host(self):
        self._saved_smtp()
        from app import email_notify
        with patch.object(email_notify, "send_test") as send_test:
            r = self.client.post("/email/test", json={"smtp_host": "smtp.attacker.example", "smtp_password": ""})
        self.assertEqual(r.status_code, 400)
        self.assertIn("password", r.get_json()["error"])
        send_test.assert_not_called()
        self.assertEqual(config.SMTP_HOST, "mail.example.org")

    def test_saved_password_is_not_sent_for_a_new_address_on_another_server(self):
        self._saved_smtp()
        from app import email_notify
        with patch.object(email_notify, "send_test") as send_test:
            r = self.client.post("/email/test", json={"smtp_user": "someone@gmail.com", "smtp_host": "mail.example.org"})
        self.assertEqual(r.status_code, 400)
        send_test.assert_not_called()
        self.assertEqual(config.SMTP_USER, "alex@example.org")

    def test_same_server_or_a_typed_password_still_tests(self):
        self._saved_smtp()
        from app import email_notify
        with patch.object(email_notify, "send_test") as send_test:
            same = self.client.post("/email/test", json={"smtp_host": "mail.example.org", "smtp_port": "465"})
            typed = self.client.post("/email/test", json={"smtp_host": "smtp.other.example", "smtp_password": "new-pw"})
        self.assertEqual(same.status_code, 200)
        self.assertEqual(typed.status_code, 200)
        self.assertEqual(send_test.call_count, 2)
        self.assertEqual(config.SMTP_PASSWORD, "new-pw")

    def test_test_email_with_no_security_keeps_checks_on(self):
        self._saved_smtp()
        from app import email_notify
        with patch.object(email_notify, "send_test"):
            self.client.post("/email/test", json={"smtp_host": "mail.example.org", "smtp_security": "none",
                                                  "smtp_tls_verify": "false"})
        self.assertEqual(config.SMTP_TLS_VERIFY, "true")

    # Sync schedule

    def test_bad_sync_time_is_refused(self):
        config.set("SYNC_TIME", "06:00")
        config.set("SYNC_FREQUENCY", "24")
        r = self.client.post("/setup/sync", data={"sync_time": "25:00", "sync_frequency": "12"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("HH:MM", r.get_data(as_text=True))
        self.assertEqual((config.SYNC_TIME, config.SYNC_FREQUENCY), ("06:00", "24"))

    def test_bad_frequency_is_refused(self):
        config.set("SYNC_FREQUENCY", "24")
        r = self.client.post("/setup/sync", data={"sync_time": "07:00", "sync_frequency": "weekly"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(config.SYNC_FREQUENCY, "24")

    def test_good_schedule_is_saved(self):
        r = self.client.post("/setup/sync", data={"sync_time": "7:30", "sync_frequency": "6"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual((config.SYNC_TIME, config.SYNC_FREQUENCY), ("07:30", "6"))

    def test_manual_only_keeps_the_saved_time(self):
        config.set("SYNC_TIME", "05:45")
        r = self.client.post("/setup/sync", data={"sync_time": "", "sync_frequency": "0"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual((config.SYNC_TIME, config.SYNC_FREQUENCY), ("05:45", "0"))

    def test_status_page_survives_an_unreadable_saved_schedule(self):
        config.SYNC_TIME, config.SYNC_FREQUENCY = "nonsense", "weekly"
        self.assertEqual(self.server._get_sync_times(), "06:00")


if __name__ == "__main__":
    unittest.main()
