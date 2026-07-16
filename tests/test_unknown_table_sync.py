"""Regression tests for the unknown-table sync patch.

Actual 26.4.0 introduced the experimental Payee Locations feature and with it
a payee_locations table. actualpy (through 0.22.3) has no model for it, so
Actual.apply_changes raises "Could not find table 'payee_locations' on the
database model" on the first sync message touching it, and every budget
download fails. The patch drops messages for tables missing from actualpy's
model registry and applies the rest. See app.sync._patch_unknown_table_sync.
"""
import unittest

from actual import Actual

import app.sync as sync_mod


class _Message:
    def __init__(self, dataset):
        self.dataset = dataset


class UnknownTableSyncTest(unittest.TestCase):
    def setUp(self):
        # Substitute a recorder as the 'original' the patch wraps, so the test
        # only exercises the filtering and not actualpy's database plumbing.
        self._true_apply_changes = Actual.apply_changes
        self._was_patched = sync_mod._apply_changes_patched
        self.received = []

        def _recorder(instance, messages):
            self.received.append(list(messages))
            return messages

        Actual.apply_changes = _recorder
        sync_mod._apply_changes_patched = False
        sync_mod._patch_unknown_table_sync()

    def tearDown(self):
        Actual.apply_changes = self._true_apply_changes
        sync_mod._apply_changes_patched = self._was_patched

    def _datasets_passed_through(self, messages):
        Actual.apply_changes(None, messages)
        return [m.dataset for m in self.received[-1]]

    def test_unknown_table_messages_are_dropped(self):
        """The exact production case: payee_locations messages in the stream."""
        messages = [
            _Message("transactions"),
            _Message("payee_locations"),
            _Message("payees"),
        ]
        self.assertEqual(
            self._datasets_passed_through(messages), ["transactions", "payees"]
        )

    def test_prefs_messages_are_kept(self):
        """'prefs' is not a model table but apply_changes handles it specially."""
        messages = [_Message("prefs"), _Message("payee_locations")]
        self.assertEqual(self._datasets_passed_through(messages), ["prefs"])

    def test_known_tables_pass_through_untouched(self):
        datasets = ["accounts", "transactions", "payees", "rules"]
        self.assertEqual(
            self._datasets_passed_through([_Message(d) for d in datasets]), datasets
        )

    def test_payee_locations_still_unknown_upstream(self):
        """When this fails, actualpy has gained payee_locations support and
        _patch_unknown_table_sync no longer needs to cover for it."""
        from actual.database import __TABLE_COLUMNS_MAP__ as table_map

        self.assertNotIn("payee_locations", table_map)

    def test_ensure_helper_installs_the_patch(self):
        self.assertTrue(sync_mod._apply_changes_patched)
        sync_mod.ensure_actual_compat_patches()  # idempotent, must not raise
        self.assertEqual(Actual.apply_changes.__name__, "_apply_changes")


if __name__ == "__main__":
    unittest.main()
