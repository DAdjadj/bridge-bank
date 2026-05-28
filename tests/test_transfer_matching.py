import datetime
import unittest
from types import SimpleNamespace

from app.sync import _find_transfer_pairs


def txn(txn_id, account_id, amount, date, **overrides):
    data = {
        "id": txn_id,
        "acct": account_id,
        "amount": amount,
        "financial_id": f"bank-{txn_id}",
        "cleared": 1,
        "transferred_id": None,
        "is_parent": 0,
        "is_child": 0,
        "starting_balance_flag": 0,
        "reconciled": 0,
    }
    data.update(overrides)
    obj = SimpleNamespace(**data)
    obj.get_date = lambda: datetime.date.fromisoformat(date)
    return obj


class TransferMatchingTest(unittest.TestCase):
    def test_finds_unique_opposite_amount_pair_in_different_accounts(self):
        source = txn("source", "checking", -2500, "2026-05-01")
        dest = txn("dest", "savings", 2500, "2026-05-03")

        pairs = _find_transfer_pairs([source, dest], {"checking", "savings"})

        self.assertEqual(pairs, [(source, dest)])

    def test_ignores_ambiguous_matches(self):
        source = txn("source", "checking", -2500, "2026-05-01")
        dest_one = txn("dest-one", "savings", 2500, "2026-05-02")
        dest_two = txn("dest-two", "cash", 2500, "2026-05-02")

        pairs = _find_transfer_pairs(
            [source, dest_one, dest_two],
            {"checking", "savings", "cash"},
        )

        self.assertEqual(pairs, [])

    def test_ignores_transactions_that_are_already_transfers(self):
        source = txn("source", "checking", -2500, "2026-05-01", transferred_id="dest")
        dest = txn("dest", "savings", 2500, "2026-05-01", transferred_id="source")

        pairs = _find_transfer_pairs([source, dest], {"checking", "savings"})

        self.assertEqual(pairs, [])

    def test_requires_imported_bank_transactions(self):
        source = txn("source", "checking", -2500, "2026-05-01", financial_id=None)
        dest = txn("dest", "savings", 2500, "2026-05-01")

        pairs = _find_transfer_pairs([source, dest], {"checking", "savings"})

        self.assertEqual(pairs, [])

    def test_ignores_pairs_outside_match_window(self):
        source = txn("source", "checking", -2500, "2026-05-01")
        dest = txn("dest", "savings", 2500, "2026-05-05")

        pairs = _find_transfer_pairs([source, dest], {"checking", "savings"})

        self.assertEqual(pairs, [])


if __name__ == "__main__":
    unittest.main()
