import unittest

from app.sync import _record_reconciled_transaction


class FakeTransaction:
    def __init__(self, txn_id, changed=False):
        self.id = txn_id
        self._changed = changed
        self.changed_calls = 0

    def changed(self):
        self.changed_calls += 1
        return self._changed


class SyncCountingTest(unittest.TestCase):
    def test_new_transaction_counts_as_added(self):
        txn = FakeTransaction("new")
        existing_ids = {"existing"}
        recorded = []

        result = _record_reconciled_transaction(txn, existing_ids, recorded)

        self.assertEqual(result, "added")
        self.assertIn("new", existing_ids)
        self.assertEqual(recorded, [txn])
        self.assertEqual(txn.changed_calls, 0)

    def test_changed_existing_transaction_counts_as_updated(self):
        txn = FakeTransaction("existing", changed=True)
        existing_ids = {"existing"}
        recorded = []

        result = _record_reconciled_transaction(txn, existing_ids, recorded)

        self.assertEqual(result, "updated")
        self.assertEqual(recorded, [txn])
        self.assertEqual(txn.changed_calls, 1)

    def test_unchanged_existing_transaction_is_skipped(self):
        txn = FakeTransaction("existing", changed=False)
        existing_ids = {"existing"}
        recorded = []

        result = _record_reconciled_transaction(txn, existing_ids, recorded)

        self.assertEqual(result, "skipped")
        self.assertEqual(recorded, [])
        self.assertEqual(txn.changed_calls, 1)


if __name__ == "__main__":
    unittest.main()
