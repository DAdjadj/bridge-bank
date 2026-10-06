"""Tests for finding a bank account's Actual account by id rather than name.

Looking up by name meant renaming the account in Actual made the next sync
create a fresh account under the old name and import into that. For a
balance-only account, which replaces every transaction in its Actual account,
an unrelated account later given the old name would have been wiped.
"""
import json
import tempfile
import unittest
import uuid
from unittest.mock import patch

from sqlmodel import Session, SQLModel, create_engine, select

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name
with appdb._conn() as _c:
    appdb._ensure_tables(_c)

from actual.database import Accounts
from app import sync


class ActualAccountBindingTest(unittest.TestCase):
    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        with appdb._conn() as c:
            c.execute("DELETE FROM bank_accounts")
            c.commit()
        engine = create_engine("sqlite://")
        SQLModel.metadata.create_all(engine)
        self.session = Session(engine)
        self.addCleanup(self.session.close)

    def _actual(self, name, closed=False, deleted=False):
        acct = Accounts(id=str(uuid.uuid4()), name=name, offbudget=0,
                        closed=int(closed), tombstone=int(deleted))
        self.session.add(acct)
        self.session.commit()
        return acct

    def _bank(self, actual_account, actual_account_id="", sync_mode="transactions"):
        row_id = appdb.add_bank_account("sess", str(uuid.uuid4()), "Revolut", "PT", actual_account,
                                        sync_mode=sync_mode)
        if actual_account_id:
            appdb.update_bank_account_field(row_id, "actual_account_id", actual_account_id)
        return appdb.get_bank_account(row_id)

    def _names(self):
        return sorted(a.name for a in self.session.exec(select(Accounts)).all())

    def test_first_sync_binds_the_account_found_by_name(self):
        revolut = self._actual("Revolut")
        bank = self._bank("Revolut")
        obj = sync.resolve_actual_account(self.session, bank, create=True)
        self.assertEqual(obj.id, revolut.id)
        self.assertEqual(appdb.get_bank_account(bank["id"])["actual_account_id"], revolut.id)

    def test_rename_in_actual_is_followed_and_the_stored_name_updated(self):
        acct = self._actual("Revolut")
        bank = self._bank("Revolut", acct.id)
        acct.name = "Personal"
        self.session.commit()
        obj = sync.resolve_actual_account(self.session, bank, create=True, has_history=True)
        self.assertEqual(obj.id, acct.id)
        self.assertEqual(self._names(), ["Personal"])  # no new "Revolut" created
        self.assertEqual(appdb.get_bank_account(bank["id"])["actual_account"], "Personal")
        self.assertEqual(bank["actual_account"], "Personal")  # labels for this run too

    def test_new_account_given_the_old_name_is_not_used(self):
        # The balance-only wipe: the bound account was renamed and an unrelated
        # account now carries the old name. The bound one must still win.
        acct = self._actual("eToro")
        bank = self._bank("eToro", acct.id, sync_mode="balance")
        acct.name = "Investments"
        other = self._actual("eToro")
        self.session.commit()
        obj = sync.resolve_actual_account(self.session, bank, create=True)
        self.assertEqual(obj.id, acct.id)
        self.assertNotEqual(obj.id, other.id)

    def test_deleted_account_is_reported_not_recreated(self):
        acct = self._actual("Revolut")
        bank = self._bank("Revolut", acct.id)
        acct.tombstone = 1
        self.session.commit()
        with self.assertRaises(sync.ActualAccountError) as cm:
            sync.resolve_actual_account(self.session, bank, create=True)
        self.assertIn("no longer exists", str(cm.exception))
        self.assertEqual(self.session.exec(select(Accounts).where(Accounts.tombstone == 0)).all(), [])

    def test_legacy_row_renamed_before_upgrade_is_reported_not_recreated(self):
        # Never bound (pre-upgrade), but it has synced before: the name it
        # remembers is gone because the customer renamed the account.
        self._actual("Personal")
        bank = self._bank("Revolut")
        with self.assertRaises(sync.ActualAccountError):
            sync.resolve_actual_account(self.session, bank, create=True, has_history=True)
        self.assertEqual(self._names(), ["Personal"])

    def test_brand_new_connection_still_creates_its_account(self):
        bank = self._bank("Savings")
        obj = sync.resolve_actual_account(self.session, bank, create=True)
        self.assertEqual(obj.name, "Savings")
        # Not remembered until a later sync finds it committed.
        self.assertEqual(appdb.get_bank_account(bank["id"])["actual_account_id"], "")

    def test_without_create_a_missing_new_account_is_none(self):
        bank = self._bank("Savings")
        self.assertIsNone(sync.resolve_actual_account(self.session, bank))
        self.assertEqual(self._names(), [])

    def test_bound_account_gone_falls_back_to_its_name(self):
        # Another budget file (re-imported export, new sync id): the old id is
        # gone but an account with the same name is there.
        bank = self._bank("Revolut", str(uuid.uuid4()))
        replacement = self._actual("Revolut")
        obj = sync.resolve_actual_account(self.session, bank, create=True, has_history=True)
        self.assertEqual(obj.id, replacement.id)
        self.assertEqual(appdb.get_bank_account(bank["id"])["actual_account_id"], replacement.id)

    def test_two_open_accounts_with_the_name_are_ambiguous(self):
        self._actual("Revolut")
        self._actual("Revolut")
        bank = self._bank("Revolut")
        with self.assertRaises(sync.ActualAccountError) as cm:
            sync.resolve_actual_account(self.session, bank, create=True)
        self.assertIn("2 open accounts", str(cm.exception))

    def test_closed_duplicate_does_not_make_the_name_ambiguous(self):
        self._actual("Revolut", closed=True)
        open_one = self._actual("Revolut")
        bank = self._bank("Revolut")
        self.assertEqual(sync.resolve_actual_account(self.session, bank).id, open_one.id)

    def test_closed_bound_account_is_reported(self):
        acct = self._actual("Revolut", closed=True)
        bank = self._bank("Revolut", acct.id)
        with self.assertRaises(sync.ActualAccountError) as cm:
            sync.resolve_actual_account(self.session, bank, create=True)
        self.assertIn("closed", str(cm.exception))

    def test_name_match_skips_an_account_another_bank_syncs_into(self):
        acct = self._actual("Personal")
        self._bank("Revolut", acct.id)  # already syncs into it, under a stale name
        newcomer = self._bank("Personal")
        with self.assertRaises(sync.ActualAccountError) as cm:
            sync.resolve_actual_account(self.session, newcomer, create=True)
        self.assertIn("another bank", str(cm.exception))
        self.assertEqual(self._names(), ["Personal"])

    def test_check_reports_problems_before_any_bank_is_fetched(self):
        good = self._actual("N26")
        self._actual("Personal")
        ok_bank = self._bank("N26", good.id)
        lost_bank = self._bank("Revolut")  # renamed before the upgrade
        state = {"accounts": {str(lost_bank["id"]): {"last_sync_date": "2026-10-01"}}}

        class _Client:
            def __init__(inner, session):
                inner.session = session

        import contextlib

        @contextlib.contextmanager
        def fake_client(_label):
            yield _Client(self.session)

        accounts = [ok_bank, lost_bank]
        with patch.object(sync, "_actual_client", fake_client):
            problems = sync.check_actual_accounts(accounts, state)
        self.assertEqual(list(problems), [lost_bank["id"]])
        self.assertIn("no longer exists", problems[lost_bank["id"]])


class ChangeActualAccountRouteTest(unittest.TestCase):
    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        with appdb._conn() as c:
            c.execute("DELETE FROM bank_accounts")
            c.commit()
        from app.web import server
        self.server = server
        self.client = server.app.test_client()
        self.accounts = [
            {"id": "id-personal", "name": "Personal", "closed": False},
            {"id": "id-business", "name": "Business", "closed": False},
            {"id": "id-old", "name": "Old", "closed": True},
        ]
        p = patch.object(server, "_actual_accounts", side_effect=lambda: [dict(a) for a in self.accounts])
        p.start()
        self.addCleanup(p.stop)
        self.saved_state = {}
        self.state = {}
        p1 = patch.object(sync, "_load_state", side_effect=lambda: json.loads(json.dumps(self.state)))
        p2 = patch.object(sync, "_save_state", side_effect=lambda s: self.saved_state.update(s))
        p1.start(); p2.start()
        self.addCleanup(p1.stop); self.addCleanup(p2.stop)

    def _bank(self, name, actual_id):
        row_id = appdb.add_bank_account("sess", str(uuid.uuid4()), "Revolut", "PT", name)
        appdb.update_bank_account_field(row_id, "actual_account_id", actual_id)
        return row_id

    def _post(self, account_id, actual_id):
        return self.client.post("/bank/actual-account",
                                data={"account_id": str(account_id), "actual_account_id": actual_id})

    def test_change_stores_id_and_name_and_clears_pending(self):
        row = self._bank("Personal", "id-personal")
        self.state = {"accounts": {str(row): {"pending_map": {"2026-10-05|-3.0": "t1"}, "last_sync_date": "x"}}}
        resp = self._post(row, "id-business")
        self.assertNotIn("error", resp.headers["Location"])
        stored = appdb.get_bank_account(row)
        self.assertEqual((stored["actual_account_id"], stored["actual_account"]), ("id-business", "Business"))
        self.assertEqual(self.saved_state["accounts"][str(row)]["pending_map"], {})
        self.assertEqual(self.saved_state["accounts"][str(row)]["last_sync_date"], "x")

    def test_account_another_bank_syncs_into_is_refused(self):
        self._bank("Personal", "id-personal")
        b = self._bank("Business", "id-business")
        resp = self._post(b, "id-personal")
        self.assertIn("error", resp.headers["Location"])
        self.assertEqual(appdb.get_bank_account(b)["actual_account_id"], "id-business")

    def test_closed_or_unknown_account_is_refused(self):
        row = self._bank("Personal", "id-personal")
        for target in ("id-old", "id-nope"):
            resp = self._post(row, target)
            self.assertIn("error", resp.headers["Location"])
        self.assertEqual(appdb.get_bank_account(row)["actual_account_id"], "id-personal")

    def test_detail_api_lists_open_accounts_with_holder(self):
        row = self._bank("Personal", "id-personal")
        data = self.client.get("/api/actual-accounts?detail=1").get_json()
        self.assertEqual(data, [
            {"id": "id-personal", "name": "Personal", "synced_by": row},
            {"id": "id-business", "name": "Business", "synced_by": None},
        ])


if __name__ == "__main__":
    unittest.main()
