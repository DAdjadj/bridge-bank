import datetime
import unittest
from types import SimpleNamespace

from app.sync import (
    _can_relink_imported_pair,
    _find_transfer_pairs,
    _remove_generated_counterparts,
)


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

    def test_can_include_already_transferred_imported_transactions_for_repair(self):
        source = txn("source", "checking", -2500, "2026-05-01", transferred_id="generated-in")
        dest = txn("dest", "savings", 2500, "2026-05-01", transferred_id="generated-out")

        pairs = _find_transfer_pairs(
            [source, dest],
            {"checking", "savings"},
            allow_existing_transfers=True,
        )

        self.assertEqual(pairs, [(source, dest)])

    def test_an_already_linked_pair_does_not_make_the_next_one_ambiguous(self):
        """110 moved on Monday and again on Tuesday: Monday's linked pair is no rival."""
        monday_out = txn("monday-out", "personal", -11000, "2026-07-15", transferred_id="monday-in")
        monday_in = txn("monday-in", "pro", 11000, "2026-07-15", transferred_id="monday-out")
        tuesday_out = txn("tuesday-out", "personal", -11000, "2026-07-16", transferred_id="generated-in")
        tuesday_in = txn("tuesday-in", "pro", 11000, "2026-07-16", transferred_id="self-generated")

        pairs = _find_transfer_pairs(
            [monday_out, monday_in, tuesday_out, tuesday_in],
            {"personal", "pro"},
            allow_existing_transfers=True,
        )

        self.assertEqual(pairs, [(tuesday_out, tuesday_in)])

    def test_repairs_a_transfer_a_rule_pointed_at_its_own_account(self):
        """A rule matching the bank text on both legs links the incoming leg to itself."""
        source = txn("source", "personal", -11000, "2026-07-16", transferred_id="generated-in")
        dest = txn("dest", "pro", 11000, "2026-07-16", transferred_id="self-generated")
        generated_in = txn("generated-in", "pro", 11000, "2026-07-16",
                           financial_id=None, transferred_id="source", tombstone=0)
        self_generated = txn("self-generated", "pro", -11000, "2026-07-16",
                             financial_id=None, transferred_id="dest", tombstone=0)
        txn_by_id = {t.id: t for t in [source, dest, generated_in, self_generated]}
        session = SimpleNamespace(added=[])
        session.add = session.added.append

        self.assertTrue(
            _can_relink_imported_pair(source, dest, txn_by_id, {"personal", "pro"})
        )
        removed = _remove_generated_counterparts(session, source, dest, txn_by_id)

        self.assertEqual(removed, 2)
        self.assertEqual(generated_in.tombstone, 1)
        self.assertEqual(self_generated.tombstone, 1)

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

    def test_removes_generated_counterparts_before_relinking_bank_sides(self):
        source = txn("source", "checking", -2500, "2026-05-01", transferred_id="generated-in")
        dest = txn("dest", "savings", 2500, "2026-05-01", transferred_id="generated-out")
        generated_in = txn(
            "generated-in",
            "savings",
            2500,
            "2026-05-01",
            financial_id=None,
            transferred_id="source",
            tombstone=0,
        )
        generated_out = txn(
            "generated-out",
            "checking",
            -2500,
            "2026-05-01",
            financial_id=None,
            transferred_id="dest",
            tombstone=0,
        )
        txn_by_id = {
            t.id: t
            for t in [source, dest, generated_in, generated_out]
        }
        session = SimpleNamespace(added=[])
        session.add = session.added.append

        self.assertTrue(
            _can_relink_imported_pair(source, dest, txn_by_id, {"checking", "savings"})
        )
        removed = _remove_generated_counterparts(session, source, dest, txn_by_id)

        self.assertEqual(removed, 2)
        self.assertEqual(generated_in.tombstone, 1)
        self.assertEqual(generated_out.tombstone, 1)
        self.assertIsNone(generated_in.transferred_id)
        self.assertIsNone(generated_out.transferred_id)

    def test_does_not_relink_over_another_imported_transfer(self):
        source = txn("source", "checking", -2500, "2026-05-01", transferred_id="other")
        dest = txn("dest", "savings", 2500, "2026-05-01")
        other = txn("other", "savings", 2500, "2026-05-01")
        txn_by_id = {t.id: t for t in [source, dest, other]}

        self.assertFalse(
            _can_relink_imported_pair(source, dest, txn_by_id, {"checking", "savings"})
        )


if __name__ == "__main__":
    unittest.main()
