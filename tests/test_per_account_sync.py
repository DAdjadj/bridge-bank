"""Tests for per-account sync: run(only_account_id=...).

A per-account sync must fetch from only the chosen bank (that is the whole
point: not tripping the other banks' rate limits), while still running the
licence/seat checks and the cross-account transfer linking.
"""
import tempfile
import unittest
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name
with appdb._conn() as _c:
    appdb._ensure_tables(_c)

from app import sync


ACCOUNTS = [
    {"id": 1, "bank_name": "ING", "bank_country": "NL", "actual_account": "ING", "sync_mode": "transactions"},
    {"id": 2, "bank_name": "Openbank", "bank_country": "NL", "actual_account": "Openbank", "sync_mode": "transactions"},
    {"id": 3, "bank_name": "Revolut", "bank_country": "NL", "actual_account": "Revolut", "sync_mode": "transactions"},
]


class PerAccountSyncTest(unittest.TestCase):
    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        # Neutralise everything run() touches except the account-selection loop.
        patches = [
            patch.object(sync.licence, "validate", return_value={"valid": True}),
            patch.object(sync.licence, "get_activation_info", return_value={"is_trial": False}),
            patch.object(sync.licence, "sync_bank_seats", return_value={"ok": True}),
            patch.object(sync.db, "get_all_bank_accounts", return_value=[dict(a) for a in ACCOUNTS]),
            patch.object(sync.db, "log_sync"),
            patch.object(sync.db, "set_setting"),
            patch.object(sync, "_load_state", return_value={"accounts": {}}),
            patch.object(sync, "_save_state"),
            # Linking spans all accounts; make it a cheap no-op here.
            patch.object(sync, "_run_actual_with_retries", return_value=0),
            patch.object(sync.email_notify, "send_failure"),
            patch.object(sync.email_notify, "send_partial"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _run(self, only_account_id=None):
        with patch.object(sync, "_sync_account", return_value=(True, 1, "OK")) as m:
            sync.run(only_account_id=only_account_id)
            return [call.args[0]["id"] for call in m.call_args_list]

    def test_single_account_syncs_only_that_bank(self):
        synced = self._run(only_account_id=2)
        self.assertEqual(synced, [2])

    def test_no_argument_syncs_every_bank(self):
        synced = self._run()
        self.assertEqual(sorted(synced), [1, 2, 3])

    def test_unknown_account_syncs_nothing_and_reports_failure(self):
        with patch.object(sync, "_sync_account", return_value=(True, 1, "OK")) as m:
            ok, added, msg = sync.run(only_account_id=999)
        m.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("no longer exists", msg)

    def test_transfer_linking_still_runs_for_a_single_account(self):
        # The linking pass spans all accounts, so a per-account sync must still
        # invoke it (that is how a freshly synced leg pairs with the others).
        with patch.object(sync, "_sync_account", return_value=(True, 1, "OK")):
            sync.run(only_account_id=2)
        # _run_actual_with_retries is the linking entry point in run().
        self.assertTrue(sync._run_actual_with_retries.called)


if __name__ == "__main__":
    unittest.main()
