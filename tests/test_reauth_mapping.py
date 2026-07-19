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
        self.assertEqual(appdb.get_bank_account(b)["account_uid"], "old-uid")

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


if __name__ == "__main__":
    unittest.main()
