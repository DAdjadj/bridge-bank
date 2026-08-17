"""Tests for telling a bank's refusal apart from a user's cancellation.

The bank's reason for rejecting an authorisation exists only in the OAuth
redirect. It used to be discarded, so an outright refusal by the bank reached
the user as "cancelled or denied" and sent them to re-authorise a connection
the bank was actively rejecting. These cover the classification and the race
in which the relay poller records the generic message first.
"""
import tempfile
import unittest

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app.web import server


def _reset_flow(status="pending", outcome="", message=""):
    with appdb._conn() as conn:
        appdb._ensure_tables(conn)
        conn.execute("DELETE FROM settings")
        conn.commit()
    appdb.set_setting("auth_flow_status", status)
    appdb.set_setting("auth_flow_outcome", outcome)
    appdb.set_setting("auth_flow_message", message)


class RefusalMessageTest(unittest.TestCase):
    def test_real_cancellations_keep_the_generic_wording(self):
        for err in ("auth_cancelled", "access_denied", "cancelled", "user_cancelled"):
            self.assertEqual(server._auth_refusal_message(err), server.GENERIC_CANCEL_MESSAGE)

    def test_missing_error_keeps_the_generic_wording(self):
        self.assertEqual(server._auth_refusal_message("", ""), server.GENERIC_CANCEL_MESSAGE)
        self.assertEqual(server._auth_refusal_message(None, None), server.GENERIC_CANCEL_MESSAGE)

    def test_bank_refusal_is_named_and_does_not_blame_the_user(self):
        msg = server._auth_refusal_message("ASPSP_ERROR", "Invalid status value")
        self.assertIn("Invalid status value", msg)
        self.assertIn("refused", msg)
        self.assertNotIn("cancelled", msg.lower())

    def test_error_code_is_used_when_there_is_no_description(self):
        msg = server._auth_refusal_message("server_error", "")
        self.assertIn("server_error", msg)

    def test_long_bank_text_is_truncated(self):
        msg = server._auth_refusal_message("x", "y" * 500)
        self.assertIn("y" * 160, msg)
        self.assertNotIn("y" * 161, msg)


class MarkCancelledTest(unittest.TestCase):
    def test_first_writer_records_the_reason(self):
        _reset_flow()
        server._mark_auth_cancelled("ASPSP_ERROR", "Invalid status value")
        self.assertEqual(appdb.get_setting("auth_flow_status"), "done")
        self.assertEqual(appdb.get_setting("auth_flow_outcome"), "cancelled")
        self.assertIn("Invalid status value", appdb.get_setting("auth_flow_message"))

    def test_browser_reason_replaces_the_relay_generic_message(self):
        # The relay poller usually lands first and can only say "cancelled".
        _reset_flow(status="done", outcome="cancelled",
                    message="Bank connection was cancelled at the bank.")
        server._mark_auth_cancelled("ASPSP_ERROR", "Invalid status value")
        self.assertIn("Invalid status value", appdb.get_setting("auth_flow_message"))

    def test_generic_arrival_does_not_overwrite_a_recorded_bank_reason(self):
        specific = server._auth_refusal_message("ASPSP_ERROR", "Invalid status value")
        _reset_flow(status="done", outcome="cancelled", message=specific)
        server._mark_auth_cancelled("auth_cancelled", "")
        self.assertEqual(appdb.get_setting("auth_flow_message"), specific)

    def test_a_completed_success_is_never_rewritten(self):
        _reset_flow(status="done", outcome="success", message="")
        server._mark_auth_cancelled("ASPSP_ERROR", "Invalid status value")
        self.assertEqual(appdb.get_setting("auth_flow_outcome"), "success")
        self.assertEqual(appdb.get_setting("auth_flow_message"), "")


if __name__ == "__main__":
    unittest.main()
