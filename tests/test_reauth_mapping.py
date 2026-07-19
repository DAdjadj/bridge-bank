"""Tests for re-authorising a bank that holds several stored accounts.

Enable Banking account uids are scoped to their session, so when one auth
covers several accounts they must be refreshed together. Refreshing only the
re-authorised account leaves its siblings pointing at a uid whose session is no
longer authorised, and the bank then rejects every request for them.

These tests pin the safety rules: the mapping path only engages for a
multi-account re-auth, it refuses uids the new session did not return, it
refuses pointing two stored accounts at the same bank account, and the ordinary
single-account picker keeps its existing behaviour.
"""
import tempfile
import unittest
from unittest.mock import patch

from app import db as appdb

# server touches the database on import, so DB_PATH has to point somewhere
# writable first. Other test modules do the same, and whichever imports last
# wins for the whole run, so create the tables here too: that keeps the shared
# file usable by any module that assumes they already exist.
_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name
with appdb._conn() as _c:
    appdb._ensure_tables(_c)

from app.web import server


class _IsolatedDbTest(unittest.TestCase):
    """Re-assert our database and start every test from a clean slate."""

    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        _reset()


def _reset():
    with appdb._conn() as conn:
        appdb._ensure_tables(conn)
        conn.execute("DELETE FROM settings")
        conn.execute("DELETE FROM bank_accounts")
        conn.commit()


def _add(actual_account, bank="Openbank", country="NL", session="old-sess", uid="old-uid",
         sync_mode="transactions"):
    return appdb.add_bank_account(
        session_id=session, account_uid=uid, bank_name=bank, bank_country=country,
        actual_account=actual_account, session_expiry="2026-09-01", sync_mode=sync_mode,
    )


def _pending_reauth(account_id, accounts_json='[{"uid": "new-a"}, {"uid": "new-b"}]'):
    appdb.set_setting("pending_reauth_account_id", str(account_id))
    appdb.set_setting("pending_bank_name", "Openbank")
    appdb.set_setting("pending_bank_country", "NL")
    appdb.set_setting("pending_auth_session_id", "new-sess")
    appdb.set_setting("pending_auth_valid_until", "2026-12-01")
    appdb.set_setting("pending_auth_accounts", accounts_json)


class SiblingLookupTest(_IsolatedDbTest):

    def test_finds_accounts_at_the_same_bank(self):
        a = _add("Openbank")
        _add("Openbank Betaal")
        _pending_reauth(a)
        self.assertEqual(
            sorted(s["actual_account"] for s in server._reauth_sibling_accounts()),
            ["Openbank", "Openbank Betaal"],
        )

    def test_ignores_other_banks_and_balance_accounts(self):
        a = _add("Openbank")
        _add("Openbank Betaal")
        _add("ING", bank="ING")
        _add("Revolut", bank="Openbank", country="PT")
        _add("eToro", sync_mode="balance")
        _pending_reauth(a)
        self.assertEqual(
            sorted(s["actual_account"] for s in server._reauth_sibling_accounts()),
            ["Openbank", "Openbank Betaal"],
        )

    def test_empty_when_not_a_reauth(self):
        _add("Openbank")
        self.assertEqual(server._reauth_sibling_accounts(), [])


class MappingModeTest(_IsolatedDbTest):
    """The mapping UI must engage only when it is actually needed."""

    def setUp(self):
        super().setUp()
        self.client = server.app.test_client()

    def _get_picker(self):
        return self.client.get("/pick-account").get_data(as_text=True)

    def test_engages_for_multi_account_reauth(self):
        a = _add("Openbank")
        _add("Openbank Betaal")
        _pending_reauth(a)
        body = self._get_picker()
        self.assertIn("Reconnect your accounts", body)
        self.assertIn("map_%s" % a, body)

    def test_single_stored_account_uses_ordinary_picker(self):
        a = _add("Openbank")
        _pending_reauth(a)
        body = self._get_picker()
        self.assertIn("Choose an account", body)
        self.assertNotIn("Reconnect your accounts", body)

    def test_single_returned_account_uses_ordinary_picker(self):
        a = _add("Openbank")
        _add("Openbank Betaal")
        _pending_reauth(a, accounts_json='[{"uid": "new-a"}]')
        body = self._get_picker()
        self.assertIn("Choose an account", body)
        self.assertNotIn("Reconnect your accounts", body)


class MappingSubmitTest(_IsolatedDbTest):
    def setUp(self):
        super().setUp()
        self.client = server.app.test_client()
        # Keep the licence API and the background sync out of the test.
        self.seat = patch.object(server, "_claim_bank_seat", return_value=None)
        self.sched = patch.object(server, "_start_scheduler_if_ready")
        self.thread = patch("app.web.server.threading.Thread")
        self.seat.start(); self.sched.start(); self.thread.start()
        self.addCleanup(self.seat.stop)
        self.addCleanup(self.sched.stop)
        self.addCleanup(self.thread.stop)

    def test_refreshes_every_mapped_account(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "new-b",
        })
        for account_id, uid in ((a, "new-a"), (b, "new-b")):
            row = appdb.get_bank_account(account_id)
            self.assertEqual(row["session_id"], "new-sess")
            self.assertEqual(row["account_uid"], uid)
            self.assertEqual(row["session_expiry"], "2026-12-01")

    def test_rejects_uid_the_session_did_not_return(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "not-in-this-session",
        })
        # Nothing is written when any part of the mapping is invalid.
        self.assertEqual(appdb.get_bank_account(a)["session_id"], "old-sess")
        self.assertEqual(appdb.get_bank_account(b)["session_id"], "old-sess")

    def test_rejects_two_accounts_pointing_at_one_bank_account(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "new-a",
        })
        self.assertEqual(appdb.get_bank_account(a)["session_id"], "old-sess")
        self.assertEqual(appdb.get_bank_account(b)["session_id"], "old-sess")

    def test_unselected_account_is_left_untouched(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "",
        })
        self.assertEqual(appdb.get_bank_account(a)["account_uid"], "new-a")
        # session_id matters as much as the uid: a refreshed session on the
        # unselected account would be exactly the orphaning bug again.
        self.assertEqual(appdb.get_bank_account(b)["account_uid"], "old-uid")
        self.assertEqual(appdb.get_bank_account(b)["session_id"], "old-sess")
        self.assertEqual(appdb.get_bank_account(b)["session_expiry"], "2026-09-01")

    def test_success_clears_pending_state_and_redirects_to_status(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        resp = self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "new-b",
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/status", resp.headers["Location"])
        for key in ("pending_auth_session_id", "pending_auth_accounts",
                    "pending_auth_valid_until", "pending_reauth_account_id"):
            self.assertEqual(appdb.get_setting(key), "", key)

    def test_rejection_redirects_back_to_picker_with_error(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        resp = self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "not-in-this-session",
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertIn("error=", resp.headers["Location"])
        # The pending auth must survive a rejected submission so the user can
        # correct the mapping instead of restarting the whole authorisation.
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "new-sess")

    def test_swapping_the_two_accounts_is_allowed(self):
        # Deliberate remaps must stay possible: the stored uids can be stale or
        # wrong (that is the very situation this feature repairs), so the form
        # cannot validate against them. The row labels carry the IBANs; picking
        # the right one is the user's call, same as the ordinary picker.
        a = _add("Openbank", uid="was-a")
        b = _add("Openbank Betaal", uid="was-b")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-b", "map_%s" % b: "new-a",
        })
        self.assertEqual(appdb.get_bank_account(a)["account_uid"], "new-b")
        self.assertEqual(appdb.get_bank_account(b)["account_uid"], "new-a")

    def test_forged_key_for_other_banks_account_is_ignored(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        c = _add("ING", bank="ING", session="ing-sess", uid="ing-uid")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "new-sess", "mapping_mode": "1",
            "map_%s" % a: "new-a",
            "map_%s" % c: "new-b",   # forged: ING is not a sibling
        })
        row = appdb.get_bank_account(c)
        self.assertEqual(row["session_id"], "ing-sess")
        self.assertEqual(row["account_uid"], "ing-uid")

    def test_stale_session_submission_is_ignored(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={
            "session_id": "an-older-attempt", "mapping_mode": "1",
            "map_%s" % a: "new-a", "map_%s" % b: "new-b",
        })
        self.assertEqual(appdb.get_bank_account(a)["session_id"], "old-sess")

    def test_ordinary_picker_still_updates_only_the_reauthorised_account(self):
        a = _add("Openbank")
        b = _add("Openbank Betaal")
        _pending_reauth(a)
        self.client.post("/pick-account", data={"session_id": "new-sess", "account_uid": "new-a"})
        self.assertEqual(appdb.get_bank_account(a)["account_uid"], "new-a")
        self.assertEqual(appdb.get_bank_account(b)["account_uid"], "old-uid")


class MappingRenderTest(_IsolatedDbTest):
    """The mapping form against the account shapes Enable Banking really sends."""

    def setUp(self):
        super().setUp()
        self.client = server.app.test_client()

    def _render(self, accounts_json):
        a = _add("Openbank")
        _add("Openbank Betaal")
        _pending_reauth(a, accounts_json=accounts_json)
        return self.client.get("/pick-account").get_data(as_text=True)

    def test_iban_extracted_from_account_id_dict_and_all_account_ids(self):
        body = self._render(
            '[{"uid": "u1", "account_id": {"iban": "NL91ABNA0417164300"}, "currency": "EUR"},'
            ' {"uid": "u2", "all_account_ids":'
            '   [{"scheme_name": "IBAN", "identification": "NL39RABO0300065264"}]}]'
        )
        self.assertIn("Reconnect your accounts", body)
        self.assertIn("NL91", body)
        self.assertIn("4300", body)
        self.assertIn("NL39", body)
        self.assertIn("5264", body)

    def test_accounts_without_iban_or_name_get_fallback_labels(self):
        body = self._render('[{"uid": "u1"}, {"uid": "u2"}]')
        self.assertIn("Account 1", body)
        self.assertIn("Account 2", body)

    def test_error_query_param_is_shown_escaped(self):
        _add("Openbank")
        _add("Openbank Betaal")
        body = self.client.get(
            "/pick-account?error=<script>alert(1)</script>"
        ).get_data(as_text=True)
        # No pending auth -> redirected, no reflection either way
        self.assertNotIn("<script>alert(1)</script>", body)
        a = appdb.get_all_bank_accounts()[0]["id"]
        _pending_reauth(a)
        body = self.client.get(
            "/pick-account?error=<script>alert(1)</script>"
        ).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)


if __name__ == "__main__":
    unittest.main()
