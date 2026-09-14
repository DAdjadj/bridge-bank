"""Tests for banks that allow only one active consent.

Openbank NL revokes the previous authorisation whenever a second one is
created. Connecting two accounts one at a time therefore leaves the first
account bound to a session the bank no longer honours, while Enable Banking
still reports that session as AUTHORIZED, so nothing upstream reveals it.

Three rules are pinned here: one authorisation can connect several accounts at
once, stored accounts drifting onto different sessions is detectable locally,
and repairing that drift re-uses the surviving session instead of spending a
fresh SCA on it.

Several sessions at one bank are not always drift, though. Revolut keeps a
personal and a business profile on separate authorisations that both keep
working, so drift is only flagged on evidence, and a re-bind never offers a
bank account that a stored account already syncs.
"""
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import requests

from app import db as appdb
from app import enablebanking, sync

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
        conn.execute("DELETE FROM session_accounts")
        conn.execute("DELETE FROM sync_log")
        conn.commit()


def _add(actual_account, bank="Openbank", country="NL", session="sess-a", uid="uid-a",
         expiry="2027-03-07T10:24:32", sync_mode="transactions"):
    return appdb.add_bank_account(
        session_id=session, account_uid=uid, bank_name=bank, bank_country=country,
        actual_account=actual_account, session_expiry=expiry, sync_mode=sync_mode,
    )


def _record(session, *accounts):
    """The accounts a session was recorded with, as (uid, identification_hash) pairs."""
    appdb.record_session_accounts(
        session, [{"uid": uid, "identification_hash": ident} for uid, ident in accounts])


def _http_error(status, body=None):
    response = MagicMock(status_code=status)
    response.json.return_value = body or {}
    return requests.HTTPError(response=response)


def _refusal(label):
    """The sync-log line a bank refusing this account's authorisation leaves behind."""
    return sync._fetch_failure_message(label, _http_error(401))


def _rows():
    """Stored accounts as the Bank page sees them, last sync outcome included."""
    return server._mark_sync_failures(appdb.get_all_bank_accounts())


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
    """Two sessions at one bank is the local signal Enable Banking cannot give.

    It only counts as drift with evidence: the newest session covering the
    older row's bank account, or the bank refusing the older row outright.
    """

    def _openbank(self, stale_expiry="2027-03-07T10:24:32", live_expiry="2027-03-07T10:26:01",
                  recorded=True):
        # The older authorisation covered Openbank Betaal. The newer one covers
        # both accounts, and only Openbank was taken from it.
        _add("Openbank Betaal", session="sess-old", uid="betaal-old", expiry=stale_expiry)
        _add("Openbank", session="sess-new", uid="openbank-new", expiry=live_expiry)
        if recorded:
            _record("sess-old", ("betaal-old", "hash-betaal"))
            _record("sess-new", ("openbank-new", "hash-openbank"), ("betaal-new", "hash-betaal"))

    def test_detects_accounts_split_across_sessions(self):
        self._openbank()
        split = server._split_session_banks(_rows())
        self.assertEqual(len(split), 1)
        self.assertEqual(split[0]["bank_name"], "Openbank")
        self.assertEqual(split[0]["newest_account"], "Openbank")
        self.assertEqual(split[0]["stale_names"], ["Openbank Betaal"])
        self.assertTrue(split[0]["covered"])
        # Nothing has failed yet, so nothing may claim it stopped working.
        self.assertFalse(split[0]["stopped"])

    def test_identical_expiry_falls_back_to_the_row_order(self):
        # Some banks stamp both authorisations with the same validity, leaving
        # creation order as the only thing that says which one is current.
        self._openbank(stale_expiry="2027-03-07T10:00:00", live_expiry="2027-03-07T10:00:00")
        split = server._split_session_banks(_rows())
        self.assertEqual(split[0]["newest_account"], "Openbank")

    def test_refused_older_row_is_flagged_before_its_sessions_were_recorded(self):
        # Installations from before sessions were recorded, like the one this
        # feature was built for: the refusal is the only evidence there is.
        self._openbank(recorded=False)
        appdb.log_sync("failure", message=_refusal("Openbank (NL) → Openbank Betaal"))
        split = server._split_session_banks(_rows())
        self.assertEqual(split[0]["stale_names"], ["Openbank Betaal"])
        self.assertTrue(split[0]["stopped"])
        self.assertFalse(split[0]["covered"])

    def test_older_row_still_syncing_is_not_flagged_before_sessions_were_recorded(self):
        self._openbank(recorded=False)
        appdb.log_sync("success", message="Openbank (NL) → Openbank Betaal")
        self.assertEqual(server._split_session_banks(_rows()), [])

    def test_refusal_is_not_enough_when_the_newest_session_does_not_cover_the_account(self):
        _add("Openbank Betaal", session="sess-old", uid="betaal-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", uid="openbank-new", expiry="2027-03-07T10:26:01")
        _record("sess-new", ("openbank-new", "hash-openbank"))
        appdb.log_sync("failure", message=_refusal("Openbank (NL) → Openbank Betaal"))
        # Re-binding has nothing to move it onto; only a re-authorisation helps.
        self.assertEqual(server._split_session_banks(_rows()), [])

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


class RevolutSeparateProfilesTest(_IsolatedDbTest):
    """Revolut personal and Revolut Business are separate approvals by design.

    Each session lists only its own profile's single account and both keep
    syncing, so neither is drift to repair. The shape comes from a real
    instance (2026-09-14) where the warning could never clear: renewing either
    row only flipped which one looked older.
    """

    def setUp(self):
        super().setUp()
        self.personal = _add("Revolut", bank="Revolut", country="PT", session="411a74d0",
                             uid="personal-uid", expiry="2027-03-13T09:58:00")
        self.business = _add("Business", bank="Revolut", country="PT", session="11b6bd57",
                             uid="business-uid", expiry="2027-03-13T10:01:00")

    def _record_both(self):
        _record("411a74d0", ("personal-uid", "hash-personal"))
        _record("11b6bd57", ("business-uid", "hash-business"))

    def _business_session(self):
        return {"session_id": "11b6bd57", "status": "AUTHORIZED",
                "accounts": [{"uid": "business-uid", "identification_hash": "hash-business"}],
                "valid_until": "2027-03-13T10:01:00"}

    def _rebind(self):
        with patch("app.enablebanking.get_session", return_value=self._business_session()) as get_session:
            resp = self.client.post("/bank/rebind", data={"bank_name": "Revolut", "bank_country": "PT"})
        return get_session, resp

    def test_not_flagged_before_their_sessions_were_recorded(self):
        # The state every existing installation upgrades into.
        self.assertEqual(server._split_session_banks(_rows()), [])

    def test_not_flagged_once_their_sessions_are_recorded(self):
        self._record_both()
        self.assertEqual(server._split_session_banks(_rows()), [])

    def test_renewing_either_profile_flags_neither(self):
        self._record_both()
        appdb.update_bank_account_field(self.personal, "session_expiry", "2027-03-13T10:04:00")
        self.assertEqual(server._split_session_banks(_rows()), [])
        appdb.update_bank_account_field(self.business, "session_expiry", "2027-03-13T10:07:00")
        self.assertEqual(server._split_session_banks(_rows()), [])

    def test_refused_profile_is_not_pointed_at_the_other_profile(self):
        self._record_both()
        appdb.log_sync("failure", message=_refusal("Revolut (PT) → Revolut"))
        self.assertEqual(server._split_session_banks(_rows()), [])
        # Nor does its sync error send the user to a re-bind that cannot help.
        self.assertFalse(sync._bank_has_newer_session(appdb.get_bank_account(self.personal)))

    def test_business_accounts_left_unconnected_are_not_offered_to_the_personal_profile(self):
        # A business session can cover more accounts than were connected. Those
        # are free, but they are not the personal account.
        _record("411a74d0", ("personal-uid", "hash-personal"))
        _record("11b6bd57", ("business-uid", "hash-business"), ("business-usd", "hash-business-usd"))
        appdb.log_sync("failure", message=_refusal("Revolut (PT) → Revolut"))
        self.assertEqual(server._split_session_banks(_rows()), [])

    def test_rebind_explains_separate_connections_and_changes_nothing(self):
        get_session, resp = self._rebind()
        # Nothing on the newest session is free, so the older one is never read.
        get_session.assert_called_once_with("11b6bd57")
        location = unquote(resp.headers["Location"])
        self.assertIn("/bank?notice=", location)
        self.assertIn("Nothing to re-bind at Revolut", location)
        self.assertIn("Revolut is on a separate connection that your newest one does not cover", location)
        for key in ("pending_auth_accounts", "pending_auth_session_id", "pending_rebind",
                    "pending_reauth_account_id"):
            self.assertEqual(appdb.get_setting(key), "", key)
        for account_id, session, uid in ((self.personal, "411a74d0", "personal-uid"),
                                         (self.business, "11b6bd57", "business-uid")):
            row = appdb.get_bank_account(account_id)
            self.assertEqual((row["session_id"], row["account_uid"]), (session, uid))

    def test_rebind_left_pending_by_the_previous_release_clears_with_an_explanation(self):
        # Re-bind pressed on v2026.09.08 and its mapping screen abandoned,
        # leaving the "Almost done" banner up. That state holds the Business
        # session's one account, read back then without an identification_hash.
        for key, value in (("pending_rebind", "1"), ("pending_bank_name", "Revolut"),
                           ("pending_bank_country", "PT"), ("pending_auth_session_id", "11b6bd57"),
                           ("pending_auth_valid_until", "2027-03-13T10:01:00"),
                           ("pending_reauth_account_id", str(self.business)),
                           ("pending_auth_accounts", json.dumps([{"uid": "business-uid"}]))):
            appdb.set_setting(key, value)
        resp = self.client.get("/pick-account")
        location = unquote(resp.headers["Location"])
        self.assertIn("/bank?notice=Nothing to re-bind at Revolut: Revolut is on a separate connection", location)
        for key in server.REBIND_PENDING_KEYS:
            self.assertEqual(appdb.get_setting(key), "", key)
        self.assertEqual(appdb.get_bank_account(self.personal)["account_uid"], "personal-uid")

    def test_one_rebind_settles_a_refused_profile_for_good(self):
        # Before anything was recorded, a refusal is all the Bank page can go
        # on, so it offers the re-bind once. The re-bind reads the newest
        # session, says it cannot help, and the warning does not come back.
        appdb.log_sync("failure", message=_refusal("Revolut (PT) → Revolut"))
        self.assertEqual(len(server._split_session_banks(_rows())), 1)
        _, resp = self._rebind()
        location = unquote(resp.headers["Location"])
        self.assertIn("re-binding cannot repair it. Re-authorise it instead", location)
        self.assertEqual(server._split_session_banks(_rows()), [])


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

    def test_newer_session_covering_the_same_account_is_one(self):
        old = _add("Openbank Betaal", session="sess-old", uid="betaal-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", uid="openbank-new", expiry="2027-03-07T10:26:01")
        _record("sess-old", ("betaal-old", "hash-betaal"))
        _record("sess-new", ("openbank-new", "hash-openbank"), ("betaal-new", "hash-betaal"))
        self.assertTrue(sync._bank_has_newer_session(self._account(old)))

    def test_newer_session_covering_only_its_own_account_is_not_one(self):
        old = _add("Openbank Betaal", session="sess-old", uid="betaal-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", uid="openbank-new", expiry="2027-03-07T10:26:01")
        _record("sess-new", ("openbank-new", "hash-openbank"))
        self.assertFalse(sync._bank_has_newer_session(self._account(old)))


class AuthRefusalRecognitionTest(unittest.TestCase):
    """The Bank page reads refusals out of the sync log, so the wording that
    marks one is pinned against the messages sync actually writes."""

    OPENBANK_REFUSAL = {"error": "ASPSP_ERROR",
                        "detail": {"message": "Unauthorized, authentication failure"}}

    def test_expired_session_is_a_refusal(self):
        self.assertTrue(sync.is_auth_refusal(_refusal("Openbank (NL) → Openbank")))

    def test_bank_naming_an_authentication_failure_is_a_refusal(self):
        for newer_session in (False, True):
            with patch("app.sync._bank_has_newer_session", return_value=newer_session):
                msg = sync._fetch_failure_message("Openbank (NL) → Openbank",
                                                  _http_error(400, self.OPENBANK_REFUSAL))
            self.assertTrue(sync.is_auth_refusal(msg), msg)

    def test_bank_side_fault_is_not_a_refusal(self):
        msg = sync._fetch_failure_message(
            "Openbank (NL) → Openbank",
            _http_error(400, {"error": "ASPSP_ERROR", "detail": {"message": "Invalid status value"}}))
        self.assertFalse(sync.is_auth_refusal(msg))
        self.assertFalse(sync.is_auth_refusal(sync._fetch_failure_message(
            "Openbank (NL) → Openbank", _http_error(429))))


class RebindRouteTest(_IsolatedDbTest):
    """Repairing a split bank must not cost a fresh authorisation."""

    def setUp(self):
        super().setUp()
        self.stale = _add("Openbank Betaal", session="sess-old", uid="old-uid",
                          expiry="2027-03-07T10:24:32")
        self.live = _add("Openbank", session="sess-new", uid="new-b",
                         expiry="2027-03-07T10:26:01")
        # Recorded when the older authorisation completed.
        _record("sess-old", ("old-uid", "hash-betaal"))

    def _session(self, accounts=None, valid_until="2027-03-07T10:26:01"):
        # Account uids are new in every session; identification_hash is what
        # says new-a is the bank account Openbank Betaal syncs.
        return {
            "session_id": "sess-new",
            "status": "AUTHORIZED",
            "accounts": accounts if accounts is not None else [
                {"uid": "new-a", "identification_hash": "hash-betaal"},
                {"uid": "new-b", "identification_hash": "hash-openbank"}],
            "valid_until": valid_until,
        }

    def _rebind(self, session=None, error=None, sessions=None):
        if sessions is not None:
            def read(session_id):
                found = sessions[session_id]
                if isinstance(found, Exception):
                    raise found
                return found
            kwargs = {"side_effect": read}
        elif error is not None:
            kwargs = {"side_effect": error}
        else:
            kwargs = {"return_value": session if session is not None else self._session()}
        with patch("app.enablebanking.get_session", **kwargs) as get_session:
            resp = self.client.post("/bank/rebind",
                                    data={"bank_name": "Openbank", "bank_country": "NL"})
        return get_session, resp

    def _seats_and_sync_patched(self):
        for p in (patch.object(server, "_claim_bank_seat", return_value=None),
                  patch.object(server, "_start_scheduler_if_ready"),
                  patch("app.web.server.threading.Thread")):
            p.start()
            self.addCleanup(p.stop)

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
        # Openbank is already on the newest connection. Offering it a remap
        # only invites pointing two accounts at one bank account.
        self.assertNotIn("map_%s" % self.live, body)

    def test_only_the_account_not_connected_yet_is_offered_and_it_is_preselected(self):
        self._rebind()
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn('value="new-a" selected', body)
        self.assertIn("the same bank account", body)
        self.assertNotIn('value="new-b"', body)
        # Abandoning the screen has a way out that needs no bank login.
        self.assertIn('name="action" value="cancel"', body)

    def test_mapping_engages_even_when_the_session_returns_one_account(self):
        # Without the re-bind flag this falls through to the single-account
        # picker, which would repoint one row and leave the other orphaned.
        self._rebind(session=self._session(accounts=[{"uid": "new-a", "identification_hash": "hash-betaal"}]))
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn("Reconnect your accounts", body)

    def test_newest_session_is_recorded(self):
        self._rebind()
        self.assertEqual(appdb.get_session_accounts()["sess-new"],
                         [{"uid": "new-a", "identification_hash": "hash-betaal"},
                          {"uid": "new-b", "identification_hash": "hash-openbank"}])

    def test_linking_the_account_another_row_syncs_is_refused(self):
        # The duplication path: a form (stale, or from before this fix) that
        # points Openbank Betaal at Openbank's bank account while Openbank
        # keeps it would import Openbank's transactions twice.
        self._rebind()
        self._seats_and_sync_patched()
        resp = self.client.post("/pick-account", data={
            "session_id": "sess-new", "mapping_mode": "1",
            "map_%s" % self.stale: "new-b",
        })
        location = unquote(resp.headers["Location"])
        self.assertIn("/pick-account?error=", location)
        self.assertIn('already syncs into "Openbank"', location)
        self.assertEqual(appdb.get_bank_account(self.stale)["account_uid"], "old-uid")
        self.assertEqual(appdb.get_bank_account(self.stale)["session_id"], "sess-old")
        self.assertEqual(appdb.get_bank_account(self.live)["account_uid"], "new-b")

    def test_older_session_never_recorded_is_read_to_match_its_account(self):
        _reset()
        self.stale = _add("Openbank Betaal", session="sess-old", uid="old-uid", expiry="2027-03-07T10:24:32")
        self.live = _add("Openbank", session="sess-new", uid="new-b", expiry="2027-03-07T10:26:01")
        get_session, resp = self._rebind(sessions={
            "sess-new": self._session(),
            "sess-old": {"session_id": "sess-old", "status": "AUTHORIZED", "valid_until": "",
                         "accounts": [{"uid": "old-uid", "identification_hash": "hash-betaal"}]},
        })
        self.assertEqual([c.args[0] for c in get_session.call_args_list], ["sess-new", "sess-old"])
        self.assertIn("/pick-account", resp.headers["Location"])
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn('value="new-a" selected', body)

    def test_unreadable_older_session_is_only_offered_a_move_once_the_bank_refuses_it(self):
        _reset()
        self.stale = _add("Openbank Betaal", session="sess-old", uid="old-uid", expiry="2027-03-07T10:24:32")
        self.live = _add("Openbank", session="sess-new", uid="new-b", expiry="2027-03-07T10:26:01")
        sessions = {"sess-new": self._session(), "sess-old": requests.HTTPError("404 Not Found")}
        # Still syncing and impossible to match: left alone.
        _, resp = self._rebind(sessions=sessions)
        location = unquote(resp.headers["Location"])
        self.assertIn("Nothing to re-bind at Openbank", location)
        self.assertIn("does not seem to cover", location)
        self.assertEqual(appdb.get_setting("pending_rebind"), "")
        # Refused by the bank: offered, but not guessed for the user.
        appdb.log_sync("failure", message=_refusal("Openbank (NL) → Openbank Betaal"))
        _, resp = self._rebind(sessions=sessions)
        self.assertIn("/pick-account", resp.headers["Location"])
        body = self.client.get("/pick-account").get_data(as_text=True)
        self.assertIn('value="new-a"', body)
        self.assertNotIn('value="new-a" selected', body)
        self.assertNotIn('value="new-b"', body)
        self.assertIn("could not confirm", body)

    def test_pending_rebind_with_nothing_left_to_move_is_cleared(self):
        self._rebind()
        # Fixed some other way before the mapping screen was used.
        appdb.update_bank_account_field(self.stale, "session_id", "sess-new")
        appdb.update_bank_account_field(self.stale, "account_uid", "new-a")
        resp = self.client.get("/pick-account")
        self.assertIn("/bank?notice=Nothing is left to re-bind at Openbank",
                      unquote(resp.headers["Location"]))
        for key in server.REBIND_PENDING_KEYS:
            self.assertEqual(appdb.get_setting(key), "", key)

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
    def _bank_page(self, failures=()):
        appdb.set_setting("eb_pem_content", "-----BEGIN PRIVATE KEY-----")
        with patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 2, "limit": 2})), \
             patch.object(server, "_get_days_left", return_value=300), \
             patch.object(server, "_last_run_failure_messages", return_value=list(failures)):
            return self.client.get("/bank").get_data(as_text=True)

    def test_split_bank_offers_the_rebind_button(self):
        _add("Openbank Betaal", session="sess-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", expiry="2027-03-07T10:26:01")
        body = self._bank_page(failures=[_refusal("Openbank (NL) → Openbank Betaal")])
        self.assertIn("/bank/rebind", body)
        self.assertIn("Re-bind to the newest connection", body)
        self.assertIn("accounts are on different connections", body)
        self.assertIn("Your bank is refusing that older connection", body)

    def test_split_that_still_syncs_does_not_claim_it_stopped(self):
        _add("Openbank Betaal", session="sess-old", uid="betaal-old", expiry="2027-03-07T10:24:32")
        _add("Openbank", session="sess-new", uid="openbank-new", expiry="2027-03-07T10:26:01")
        _record("sess-old", ("betaal-old", "hash-betaal"))
        _record("sess-new", ("openbank-new", "hash-openbank"), ("betaal-new", "hash-betaal"))
        body = self._bank_page()
        self.assertIn("Re-bind to the newest connection", body)
        self.assertIn("the newest connection covers it too", body)
        self.assertNotIn("refusing", body)

    def test_separate_revolut_profiles_show_no_rebind_warning(self):
        _add("Revolut", bank="Revolut", country="PT", session="411a74d0", uid="personal-uid",
             expiry="2027-03-13T09:58:00")
        _add("Business", bank="Revolut", country="PT", session="11b6bd57", uid="business-uid",
             expiry="2027-03-13T10:01:00")
        body = self._bank_page()
        self.assertNotIn("/bank/rebind", body)
        self.assertNotIn("different connections", body)

    def test_rebind_notice_is_shown_as_information(self):
        appdb.set_setting("eb_pem_content", "-----BEGIN PRIVATE KEY-----")
        with patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 0, "limit": 2})), \
             patch.object(server, "_get_days_left", return_value=None), \
             patch.object(server, "_last_run_failure_messages", return_value=[]):
            body = self.client.get("/bank?notice=Nothing%20to%20re-bind%20at%20Revolut").get_data(as_text=True)
        self.assertIn('<div class="alert alert-info">Nothing to re-bind at Revolut</div>', body)

    def test_abandoned_rebind_offers_to_continue_or_cancel(self):
        _add("Openbank", session="sess-new", uid="new-b")
        appdb.set_setting("pending_rebind", "1")
        appdb.set_setting("pending_bank_name", "Openbank")
        appdb.set_setting("pending_auth_session_id", "sess-new")
        appdb.set_setting("pending_auth_accounts", json.dumps([{"uid": "new-a"}, {"uid": "new-b"}]))
        body = self._bank_page()
        self.assertIn("finish re-binding your Openbank accounts", body)
        self.assertNotIn("your bank returned several accounts", body)
        self.assertIn('name="action" value="cancel"', body)
        # Cancelling a re-bind gives up nothing, so it does not ask twice.
        self.assertNotIn("Cancel without connecting?", body)

    def test_status_page_shows_the_same_banner(self):
        appdb.set_setting("pending_rebind", "1")
        appdb.set_setting("pending_bank_name", "Openbank")
        appdb.set_setting("pending_auth_accounts", json.dumps([{"uid": "new-a"}]))
        info = {"usage": 1, "limit": 3, "is_trial": False, "expires_at": "",
                "bank_account_limit": 2, "bank_seat_usage": 1}
        with patch.object(server.config, "is_configured", return_value=True), \
             patch.object(server.config, "is_connected", return_value=True), \
             patch.object(server.licence, "get_activation_info", return_value=info), \
             patch.object(server.licence, "validate", return_value={"valid": True}), \
             patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 1, "limit": 2})), \
             patch.object(server, "_get_days_left", return_value=300):
            body = self.client.get("/status").get_data(as_text=True)
        self.assertIn("finish re-binding your Openbank accounts", body)
        self.assertIn('name="action" value="cancel"', body)

    def test_cancel_forgets_the_abandoned_rebind(self):
        _add("Openbank", session="sess-new", uid="new-b")
        for key, value in (("pending_rebind", "1"), ("pending_bank_name", "Openbank"),
                           ("pending_bank_country", "NL"), ("pending_auth_session_id", "sess-new"),
                           ("pending_reauth_account_id", "1"),
                           ("pending_auth_accounts", json.dumps([{"uid": "new-a"}]))):
            appdb.set_setting(key, value)
        resp = self.client.post("/bank", data={"action": "cancel"})
        self.assertIn("/bank", resp.headers["Location"])
        for key in server.REBIND_PENDING_KEYS:
            self.assertEqual(appdb.get_setting(key), "", key)
        self.assertNotIn("Almost done", self._bank_page())

    def test_starting_a_reauthorisation_forgets_an_abandoned_rebind(self):
        # Left set, the flag would turn the next authorisation's picker into a
        # re-bind of a session that is not the one just authorised.
        account = _add("Openbank", session="sess-new", uid="new-b")
        appdb.set_setting("pending_rebind", "1")
        appdb.set_setting("pending_add_from_session", "1")
        appdb.set_setting("eb_pem_content", "-----BEGIN PRIVATE KEY-----")
        with patch.object(server.licence, "validate", return_value={"valid": True}), \
             patch("app.enablebanking.start_auth", return_value={"url": "https://bank.example/auth"}), \
             patch("app.relay.launch"), \
             patch.object(server, "_get_bank_seat_error", return_value=(None, {"used": 1, "limit": 2})):
            self.client.post("/bank/reauthorise", data={
                "account_id": str(account), "bank_name": "Openbank", "bank_country": "NL"})
        self.assertEqual(appdb.get_setting("pending_rebind"), "")
        self.assertEqual(appdb.get_setting("pending_add_from_session"), "")

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


class SessionAccountsTest(_IsolatedDbTest):
    """What gets recorded about a session, and from where."""

    def test_session_read_takes_identification_hashes_from_accounts_data(self):
        # GET /sessions lists bare uids; only accounts_data says which bank
        # account each one is.
        response = MagicMock()
        response.json.return_value = {
            "session_id": "11b6bd57", "status": "AUTHORIZED",
            "accounts": ["business-uid"],
            "accounts_data": [{"uid": "business-uid", "identification_hash": "hash-business"}],
            "access": {"valid_until": "2027-03-13T10:01:00.000000+00:00"},
        }
        with patch("app.enablebanking.requests.get", return_value=response), \
             patch("app.enablebanking._make_headers", return_value={}):
            session = enablebanking.get_session("11b6bd57")
        self.assertEqual(session["accounts"],
                         [{"uid": "business-uid", "identification_hash": "hash-business"}])
        self.assertEqual(session["valid_until"], "2027-03-13T10:01:00.000000+00:00")

    def test_completed_authorisation_records_its_accounts_without_their_details(self):
        state = "11111111-2222-4333-8444-555555555555"
        appdb.set_setting("pending_session_state", state)
        appdb.set_setting("auth_flow_state_id", state)
        appdb.set_setting("auth_flow_status", "pending")
        result = {"session_id": "sess-2", "valid_until": "2027-03-07T10:24:32", "accounts": [
            {"uid": "u1", "identification_hash": "h1", "account_id": {"iban": "NL91ABNA0417164300"}},
            {"uid": "u2", "identification_hash": "h2", "account_id": {"iban": "NL39RABO0300065264"}},
        ]}
        with patch("app.enablebanking.complete_auth", return_value=result):
            outcome, _ = server._complete_auth_from_code("code-1", state)
        self.assertEqual(outcome, "picker")
        self.assertEqual(appdb.get_session_accounts()["sess-2"],
                         [{"uid": "u1", "identification_hash": "h1"},
                          {"uid": "u2", "identification_hash": "h2"}])

    def test_recording_again_replaces_the_earlier_record(self):
        _record("sess", ("u1", "h1"))
        _record("sess", ("u1", "h1"), ("u2", "h2"))
        self.assertEqual(len(appdb.get_session_accounts()["sess"]), 2)


if __name__ == "__main__":
    unittest.main()
