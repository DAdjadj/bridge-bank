import unittest
from unittest.mock import patch

from app import sync
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


class ActualRetryTest(unittest.TestCase):
    def test_retries_transient_timeout(self):
        calls = []

        def operation():
            calls.append("call")
            if len(calls) == 1:
                raise TimeoutError("The read operation timed out")
            return "ok"

        with patch.object(sync, "ACTUAL_RETRY_DELAYS_SECONDS", (0,)), \
             patch.object(sync.time, "sleep") as sleep:
            result = sync._run_actual_with_retries("Actual", operation)

        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 2)
        sleep.assert_called_once_with(0)

    def test_does_not_retry_non_transient_error(self):
        calls = []

        def operation():
            calls.append("call")
            raise ValueError("bad configuration")

        with patch.object(sync, "ACTUAL_RETRY_DELAYS_SECONDS", (0,)), \
             patch.object(sync.time, "sleep") as sleep:
            with self.assertRaises(ValueError):
                sync._run_actual_with_retries("Actual", operation)

        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
