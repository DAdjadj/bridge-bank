"""Tests for banks that allow only one active consent.

Openbank NL revokes the previous authorisation whenever a second one is
created. Connecting two accounts one at a time therefore leaves the first
account bound to a session the bank no longer honours, while Enable Banking
still reports that session as AUTHORIZED, so nothing upstream reveals it.

Three rules are pinned here: one authorisation can connect several accounts at
once, stored accounts drifting onto different sessions is detectable locally,
and repairing that drift re-uses the surviving session instead of spending a
fresh SCA on it.
"""
import json
import tempfile
import unittest
from unittest.mock import patch

from app import db as appdb
from app import sync

# server touches the database on import, so DB_PATH has to point somewhere
# writable first. Other test modules do the same, and whichever imports last
# wins for the whole run, so create the tables here too.
_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name
with appdb._conn() as _c:
    appdb._ensure_tables(_c)

from app.web import server

TWO_ACCOUNTS = json.dumps([
    {"uid": "u1", "account_id": {"iban": "NL91ABNA0417164300"}, "currency": "EUR"},
    {"uid": "u2", "account_id": {"iban": "NL39RABO0300065264"}, "currency": "EUR"},
])


def _reset():
    with appdb._conn() as conn:
        appdb._ensure_tables(conn)
        conn.execute("DELETE FROM settings")
        conn.execute("DELETE FROM bank_accounts")
        conn.commit()


def _add(actual_account, bank="Openbank", country="NL", session="sess-a", uid="uid-a",
         expiry="2027-03-07T10:24:32", sync_mode="transactions"):
    return appdb.add_bank_account(
        session_id=session, account_uid=uid, bank_name=bank, bank_country=country,
        actual_account=actual_account, session_expiry=expiry, sync_mode=sync_mode,
    )


def _pending_connect(accounts_json=TWO_ACCOUNTS):
    """State left behind by a first-time connection, with no account stored yet."""
    appdb.set_setting("pending_bank_name", "Openbank")
    appdb.set_setting("pending_bank_country", "NL")
    appdb.set_setting("pending_actual_account", "Openbank")
    appdb.set_setting("pending_start_sync_date", "2026-09-01")
    appdb.set_setting("pending_auth_session_id", "new-sess")
    appdb.set_setting("pending_auth_valid_until", "2027-03-07T10:24:32")
    appdb.set_setting("pending_auth_accounts", accounts_json)


class _IsolatedDbTest(unittest.TestCase):
    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        _reset()
        self.client = server.app.test_client()


class MultiConnectPickerTest(_IsolatedDbTest):
    """A first connection offers every account the authorisation returned."""

    def test_offers_all_accounts_when_nothing_is_stored_yet(self):
        _pending_connect()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Choose your accounts", body)
        self.assertIn('name="multi_mode"', body)
        self.assertIn('type="checkbox"', body)
        self.assertIn('value="u1"', body)
        self.assertIn('value="u2"', body)
        self.assertIn("NL91", body)
        self.assertIn("5264", body)

    def test_actual_account_from_the_bank_page_is_prefilled_once(self):
        _pending_connect()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn('name="actual_u1"', body)
        self.assertIn('name="actual_u2"', body)
        self.assertEqual(body.count('value="Openbank"'), 1)

    def test_reauth_still_uses_the_single_account_picker(self):
        # Re-authorising one stored account must not turn into a bulk connect.
        a = _add("Openbank")
        appdb.set_setting("pending_reauth_account_id", str(a))
        _pending_connect()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Choose an account", body)
        self.assertNotIn("Choose your accounts", body)


class MultiConnectSubmitTest(_IsolatedDbTest):
    def setUp(self):
        super().setUp()
        # Keep the licence API, Actual Budget and the background sync out.
        self.seat = patch.object(server, "_claim_bank_seat", return_value=None)
        self.capacity = patch.object(server, "_ensure_global_bank_capacity", return_value=None)
        self.names = patch.object(server, "_actual_account_names", return_value=[])
        self.sched = patch.object(server, "_start_scheduler_if_ready")
        self.thread = patch("app.web.server.threading.Thread")
        for p in (self.seat, self.names, self.sched, self.thread):
            p.start()
            self.addCleanup(p.stop)
        self.capacity_mock = self.capacity.start()
        self.addCleanup(self.capacity.stop)

    def _post(self, data):
        payload = {"session_id": "new-sess", "multi_mode": "1"}
        payload.update(data)
        return self.client.post("/pick-account", data=payload)

    def test_two_accounts_are_created_on_one_session(self):
        _pending_connect()
        self._post({"account_uid": ["u1", "u2"],
                    "actual_u1": "Openbank", "actual_u2": "Openbank Betaal"})
        rows = appdb.get_all_bank_accounts()
        self.assertEqual(len(rows), 2)
        # One session for both rows is the whole point: a second authorisation
        # is what revokes the first at a one-consent bank.
        self.assertEqual({r["session_id"] for r in rows}, {"new-sess"})
        self.assertEqual({r["account_uid"] for r in rows}, {"u1", "u2"})
        self.assertEqual(sorted(r["actual_account"] for r in rows),
                         ["Openbank", "Openbank Betaal"])
        for row in rows:
            self.assertEqual(row["bank_name"], "Openbank")
            self.assertEqual(row["bank_country"], "NL")
            self.assertEqual(row["session_expiry"], "2027-03-07T10:24:32")
            self.assertEqual(row["start_sync_date"], "2026-09-01")

    def test_only_the_selected_accounts_are_created(self):
        _pending_connect()
        self._post({"account_uid": ["u2"], "actual_u2": "Openbank Betaal"})
        rows = appdb.get_all_bank_accounts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["account_uid"], "u2")

    def test_seats_are_requested_for_every_selected_account(self):
        _pending_connect()
        self._post({"account_uid": ["u1", "u2"],
                    "actual_u1": "Openbank", "actual_u2": "Openbank Betaal"})
        self.assertEqual(self.capacity_mock.call_args.kwargs["new_seats"], 2)

    def test_two_accounts_cannot_share_one_actual_account(self):
        _pending_connect()
        resp = self._post({"account_uid": ["u1", "u2"],
                           "actual_u1": "Openbank", "actual_u2": "Openbank"})
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_actual_account_already_in_use_is_refused(self):
        _add("Openbank", bank="ING", country="NL")
        _pending_connect()
        resp = self._post({"account_uid": ["u1"], "actual_u1": "openbank"})
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(len(appdb.get_all_bank_accounts()), 1)

    def test_missing_actual_account_name_is_refused(self):
        _pending_connect()
        resp = self._post({"account_uid": ["u1", "u2"],
                           "actual_u1": "Openbank", "actual_u2": "  "})
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_uid_the_session_did_not_return_is_refused(self):
        _pending_connect()
        resp = self._post({"account_uid": ["u1", "smuggled"],
                           "actual_u1": "Openbank", "actual_smuggled": "Elsewhere"})
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_nothing_selected_is_refused(self):
        _pending_connect()
        resp = self._post({"actual_u1": "Openbank"})
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_a_seat_refusal_rolls_back_the_whole_connection(self):
        # Half a connection is worse than none: the row that landed would hold
        # a seat and sync while the user believes both accounts are connected.
        _pending_connect()
        with patch.object(server, "_claim_bank_seat",
                          side_effect=[None, "Bank account limit reached (2)."]):
            resp = self._post({"account_uid": ["u1", "u2"],
                               "actual_u1": "Openbank", "actual_u2": "Openbank Betaal"})
        self.assertIn("/bank", resp.headers["Location"])
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_stale_session_submission_is_ignored(self):
        _pending_connect()
        self.client.post("/pick-account", data={
            "session_id": "an-older-attempt", "multi_mode": "1",
            "account_uid": ["u1"], "actual_u1": "Openbank",
        })
        self.assertEqual(appdb.get_all_bank_accounts(), [])

    def test_success_clears_pending_state_and_redirects_to_status(self):
        _pending_connect()
        resp = self._post({"account_uid": ["u1", "u2"],
                           "actual_u1": "Openbank", "actual_u2": "Openbank Betaal"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/status", resp.headers["Location"])
        for key in ("pending_auth_session_id", "pending_auth_accounts",
                    "pending_auth_valid_until", "pending_actual_account", "pending_rebind"):
            self.assertEqual(appdb.get_setting(key), "", key)


class SplitSessionDetectionTest(_IsolatedDbTest):
    """Two sessions at one bank is the local signal Enable Banking cannot give."""

    def test_detects_accounts_split_across_sessions(self):
        _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", expiry="2027-03-07T10:26:01")
        split = server._split_session_banks(appdb.get_all_bank_accounts())
        self.assertEqual(len(split), 1)
        self.assertEqual(split[0]["bank_name"], "Openbank")
        self.assertEqual(split[0]["newest_account"], "Openbank")
        self.assertEqual(split[0]["stale_names"], ["Openbank Betaal"])

    def test_identical_expiry_falls_back_to_the_row_order(self):
        # Some banks stamp both authorisations with the same validity, leaving
        # creation order as the only thing that says which one is current.
        _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:00:00")
        _add("Openbank", session="sess-new", expiry="2027-03-07T10:00:00")
        split = server._split_session_banks(appdb.get_all_bank_accounts())
        self.assertEqual(split[0]["newest_account"], "Openbank")

    def test_one_session_per_bank_is_not_flagged(self):
        _add("Openbank Betaal", session="sess-a")
        _add("Openbank", session="sess-a")
        _add("ING", bank="ING", session="ing-sess")
        self.assertEqual(server._split_session_banks(appdb.get_all_bank_accounts()), [])

    def test_balance_providers_and_sessionless_rows_are_ignored(self):
        _add("Openbank", session="sess-a")
        _add("eToro", bank="eToro", country="", session="", sync_mode="balance")
        self.assertEqual(server._split_session_banks(appdb.get_all_bank_accounts()), [])

    def test_same_bank_in_two_countries_is_not_a_split(self):
        _add("Openbank NL", session="sess-nl")
        _add("Openbank ES", country="ES", session="sess-es")
        self.assertEqual(server._split_session_banks(appdb.get_all_bank_accounts()), [])


class NewerSessionLookupTest(_IsolatedDbTest):
    """What tells a sync failure apart from an ordinary bank-side refusal."""

    def _account(self, account_id):
        return appdb.get_bank_account(account_id)

    def test_older_row_sees_the_newer_session(self):
        old = _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", expiry="2027-03-07T10:26:01")
        self.assertTrue(sync._bank_has_newer_session(self._account(old)))

    def test_newest_row_does_not_see_one(self):
        _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:24:32")
        new = _add("Openbank", session="sess-new", expiry="2027-03-07T10:26:01")
        self.assertFalse(sync._bank_has_newer_session(self._account(new)))

    def test_rows_sharing_a_session_are_not_a_split(self):
        a = _add("Openbank Betaal", session="sess-a")
        _add("Openbank", session="sess-a")
        self.assertFalse(sync._bank_has_newer_session(self._account(a)))

    def test_another_bank_is_not_considered(self):
        a = _add("Openbank", session="sess-old", expiry="2027-01-01T00:00:00")
        _add("ING", bank="ING", session="ing-sess", expiry="2027-12-01T00:00:00")
        self.assertFalse(sync._bank_has_newer_session(self._account(a)))

    def test_missing_account_is_not_a_split(self):
        self.assertFalse(sync._bank_has_newer_session(None))


class RebindRouteTest(_IsolatedDbTest):
    """Repairing a split bank must not cost a fresh authorisation."""

    def setUp(self):
        super().setUp()
        self.stale = _add("Openbank Betaal", session="sess-old", uid="old-uid",
                          expiry="2027-03-07T10:24:32")
        self.live = _add("Openbank", session="sess-new", uid="new-b",
                         expiry="2027-03-07T10:26:01")

    def _session(self, accounts=None, valid_until="2027-03-07T10:26:01"):
        return {
            "session_id": "sess-new",
            "status": "AUTHORIZED",
            "accounts": accounts if accounts is not None else [{"uid": "new-a"}, {"uid": "new-b"}],
            "valid_until": valid_until,
        }

    def _rebind(self, session=None, error=None):
        kwargs = ({"side_effect": error} if error is not None
                  else {"return_value": session if session is not None else self._session()})
        with patch("app.enablebanking.get_session", **kwargs) as get_session:
            resp = self.client.post("/bank/rebind",
                                    data={"bank_name": "Openbank", "bank_country": "NL"})
        return get_session, resp

    def test_reads_the_newest_session_and_opens_the_mapping_screen(self):
        get_session, resp = self._rebind()
        get_session.assert_called_once_with("sess-new")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "sess-new")
        self.assertEqual(appdb.get_setting("pending_reauth_account_id"), str(self.live))
        self.assertEqual(appdb.get_setting("pending_auth_valid_until"), "2027-03-07T10:26:01")
        self.assertEqual(appdb.get_setting("pending_rebind"), "1")

    def test_mapping_screen_says_no_new_login_is_needed(self):
        self._rebind()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Reconnect your accounts", body)
        self.assertIn("No new bank login is needed", body)
        self.assertIn("map_%s" % self.stale, body)
        self.assertIn("map_%s" % self.live, body)

    def test_mapping_engages_even_when_the_session_returns_one_account(self):
        # Without the re-bind flag this falls through to the single-account
        # picker, which would repoint one row and leave the other orphaned.
        self._rebind(session=self._session(accounts=[{"uid": "new-a"}]))
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Reconnect your accounts", body)

    def test_mapping_submit_puts_both_rows_on_the_live_session(self):
        self._rebind()
        with patch.object(server, "_claim_bank_seat", return_value=None), \
             patch.object(server, "_start_scheduler_if_ready"), \
             patch("app.web.server.threading.Thread"):
            self.client.post("/pick-account", data={
                "session_id": "sess-new", "mapping_mode": "1",
                "map_%s" % self.stale: "new-a", "map_%s" % self.live: "new-b",
            })
        rows = appdb.get_all_bank_accounts()
        self.assertEqual({r["session_id"] for r in rows}, {"sess-new"})
        self.assertEqual(appdb.get_bank_account(self.stale)["account_uid"], "new-a")
        self.assertEqual(server._split_session_banks(rows), [])
        self.assertEqual(appdb.get_setting("pending_rebind"), "")

    def test_unreadable_session_reports_back_without_touching_anything(self):
        import requests
        _, resp = self._rebind(error=requests.HTTPError("401 Unauthorized"))
        self.assertIn("/bank", resp.headers["Location"])
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "")
        self.assertEqual(appdb.get_bank_account(self.stale)["session_id"], "sess-old")

    def test_session_without_accounts_is_refused(self):
        _, resp = self._rebind(session=self._session(accounts=[]))
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "")

    def test_single_account_bank_has_nothing_to_rebind(self):
        _reset()
        _add("Openbank", session="sess-a")
        _, resp = self._rebind()
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "")


class AddFromExistingConnectionTest(_IsolatedDbTest):
    """Adding a second account must not buy a second authorisation.

    The stored session already covers every account at that bank, so the ones
    not connected yet can be taken from it. Authorising again to reach them is
    what revokes the connection the first account is using.
    """

    def setUp(self):
        super().setUp()
        self.existing = _add("Openbank", session="sess-a", uid="new-a")
        self.seat = patch.object(server, "_claim_bank_seat", return_value=None)
        self.capacity = patch.object(server, "_ensure_global_bank_capacity", return_value=None)
        self.names = patch.object(server, "_actual_account_names", return_value=[])
        self.sched = patch.object(server, "_start_scheduler_if_ready")
        self.thread = patch("app.web.server.threading.Thread")
        for p in (self.seat, self.capacity, self.names, self.sched, self.thread):
            p.start()
            self.addCleanup(p.stop)

    def _session(self, accounts=None):
        return {
            "session_id": "sess-a",
            "status": "AUTHORIZED",
            "accounts": accounts if accounts is not None else [{"uid": "new-a"}, {"uid": "new-b"}],
            "valid_until": "2027-03-07T10:24:32",
        }

    def _add_from(self, session=None, error=None, form=None):
        kwargs = ({"side_effect": error} if error is not None
                  else {"return_value": session if session is not None else self._session()})
        data = {"bank_name": "Openbank", "bank_country": "NL"}
        data.update(form or {})
        with patch("app.enablebanking.get_session", **kwargs) as get_session:
            resp = self.client.post("/bank/add-from-connection", data=data)
        return get_session, resp

    def test_offers_only_the_accounts_not_connected_yet(self):
        get_session, resp = self._add_from()
        get_session.assert_called_once_with("sess-a")
        self.assertIn("/pick-account", resp.headers["Location"])
        self.assertEqual(json.loads(appdb.get_setting("pending_auth_accounts")), [{"uid": "new-b"}])
        self.assertEqual(appdb.get_setting("pending_auth_session_id"), "sess-a")
        self.assertEqual(appdb.get_setting("pending_add_from_session"), "1")
        # Nothing is being re-authorised, so the picker must not open in
        # mapping mode and repoint the account that already works.
        self.assertEqual(appdb.get_setting("pending_reauth_account_id"), "")

    def test_picker_offers_a_single_leftover_account(self):
        # One account left is the ordinary case, and the plain single-account
        # picker has no field for its Actual Budget name.
        self._add_from()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Add another account", body)
        self.assertIn('name="multi_mode"', body)
        self.assertIn('value="new-b"', body)
        self.assertIn("needs no new bank login", body)

    def test_connecting_it_keeps_both_accounts_on_one_session(self):
        self._add_from(form={"start_sync_date": "2026-09-01"})
        self.client.post("/pick-account", data={
            "session_id": "sess-a", "multi_mode": "1",
            "account_uid": ["new-b"], "actual_new-b": "Openbank Betaal",
        })
        rows = appdb.get_all_bank_accounts()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["session_id"] for r in rows}, {"sess-a"})
        self.assertEqual({r["account_uid"] for r in rows}, {"new-a", "new-b"})
        # The state this whole feature exists to avoid.
        self.assertEqual(server._split_session_banks(rows), [])
        added = [r for r in rows if r["account_uid"] == "new-b"][0]
        self.assertEqual(added["actual_account"], "Openbank Betaal")
        self.assertEqual(added["start_sync_date"], "2026-09-01")
        self.assertEqual(added["session_expiry"], "2027-03-07T10:24:32")

    def test_the_uid_already_connected_cannot_be_connected_twice(self):
        self._add_from()
        self.client.post("/pick-account", data={
            "session_id": "sess-a", "multi_mode": "1",
            "account_uid": ["new-a"], "actual_new-a": "Openbank Again",
        })
        self.assertEqual(len(appdb.get_all_bank_accounts()), 1)

    def test_nothing_left_to_add_says_so(self):
        _, resp = self._add_from(session=self._session(accounts=[{"uid": "new-a"}]))
        self.assertIn("/bank", resp.headers["Location"])
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_accounts"), "")

    def test_unreadable_session_sends_the_user_back(self):
        import requests
        _, resp = self._add_from(error=requests.HTTPError("401 Unauthorized"))
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_accounts"), "")

    def test_bank_with_no_connection_is_refused(self):
        _reset()
        _, resp = self._add_from()
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_accounts"), "")

    def test_seat_limit_is_reported_before_the_picker(self):
        with patch.object(server, "_ensure_global_bank_capacity",
                          return_value="Bank account limit reached (2)."):
            _, resp = self._add_from()
        self.assertIn("/bank", resp.headers["Location"])
        self.assertIn("error=", resp.headers["Location"])
        self.assertEqual(appdb.get_setting("pending_auth_accounts"), "")


class ConnectedBanksTest(_IsolatedDbTest):
    def test_lists_each_connected_bank_once(self):
        _add("Openbank", session="sess-a")
        _add("Openbank Betaal", session="sess-a")
        _add("ING", bank="ING", session="ing-sess")
        _add("eToro", bank="eToro", country="", session="", sync_mode="balance")
        self.assertEqual(server._connected_banks(appdb.get_all_bank_accounts()),
                         [{"name": "Openbank", "country": "NL"},
                          {"name": "ING", "country": "NL"}])


class BankPageTest(_IsolatedDbTest):
    def test_split_bank_offers_the_rebind_button(self):
        _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", expiry="2027-03-07T10:26:01")
        appdb.set_setting("eb_pem_content", "-----BEGIN PRIVATE KEY-----")
        with patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 2, "limit": 2})), \
             patch.object(server, "_get_days_left", return_value=300), \
             patch.object(server, "_last_run_failure_messages", return_value=[]):
            body = self.client.get("/bank").get_data(as_text=True)
        self.assertIn("/bank/rebind", body)
        self.assertIn("Re-bind to the newest connection", body)
        self.assertIn("accounts are on different connections", body)

    def test_connect_form_knows_which_banks_are_already_connected(self):
        _add("Openbank", session="sess-a")
        appdb.set_setting("eb_pem_content", "-----BEGIN PRIVATE KEY-----")
        with patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 1, "limit": 2})), \
             patch.object(server, "_get_days_left", return_value=300), \
             patch.object(server, "_last_run_failure_messages", return_value=[]):
            body = self.client.get("/bank").get_data(as_text=True)
        self.assertIn('"name": "Openbank"', body)
        self.assertIn("/bank/add-from-connection", body)
        self.assertIn("revoke the first", body)


if __name__ == "__main__":
    unittest.main()
