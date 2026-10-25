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

    def test_a_shop_payment_and_a_friend_paying_back_are_not_a_transfer(self):
        """Apple charges 25.99 on one card; a friend sends 25.99 to the other account."""
        apple = txn("apple", "business", -2599, "2026-10-25", imported_description="apple.com/bill")
        miguel = txn("miguel", "personal", 2599, "2026-10-25", imported_description="Miguel Bastos")

        pairs = _find_transfer_pairs(
            [apple, miguel], {"business", "personal"},
            named_refs={"bank-apple", "bank-miguel"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [])

    def test_paying_someone_and_being_paid_by_them_is_not_a_transfer(self):
        to_paulo = txn("to-paulo", "business", -1000, "2026-10-11", imported_description="Paulo Silva")
        from_paulo = txn("from-paulo", "personal", 1000, "2026-10-12", imported_description="Paulo Silva")

        pairs = _find_transfer_pairs(
            [to_paulo, from_paulo], {"business", "personal"},
            named_refs={"bank-to-paulo", "bank-from-paulo"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [])

    def test_moves_that_name_nobody_still_pair(self):
        """Revolut's "To EUR Pro" names no counterparty on either leg."""
        out = txn("out", "personal", -7299, "2026-10-25", imported_description="To EUR Pro")
        into = txn("in", "business", 7299, "2026-10-25", imported_description="To EUR Pro")

        pairs = _find_transfer_pairs(
            [out, into], {"business", "personal"},
            named_refs={"bank-something-else"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [(out, into)])

    def test_legs_naming_the_account_holder_still_pair(self):
        out = txn("out", "n26", -44000, "2026-04-17", imported_description="DAVID ADJADJ ALVES")
        into = txn("in", "revolut", 44000, "2026-04-18", imported_description="Top-Up by *9914")

        pairs = _find_transfer_pairs(
            [out, into], {"n26", "revolut"},
            named_refs={"bank-out"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [(out, into)])

    def test_someone_elses_payment_no_longer_makes_a_real_transfer_ambiguous(self):
        out = txn("out", "personal", -7299, "2026-10-25", imported_description="To EUR Pro")
        into = txn("in", "business", 7299, "2026-10-25", imported_description="To EUR Pro")
        friend = txn("friend", "savings", 7299, "2026-10-25", imported_description="Miguel Bastos")

        pairs = _find_transfer_pairs(
            [out, into, friend], {"business", "personal", "savings"},
            named_refs={"bank-friend"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [(out, into)])

    def test_without_a_holder_name_two_different_names_never_pair(self):
        apple = txn("apple", "business", -2599, "2026-10-25", imported_description="apple.com/bill")
        miguel = txn("miguel", "personal", 2599, "2026-10-25", imported_description="Miguel Bastos")

        pairs = _find_transfer_pairs(
            [apple, miguel], {"business", "personal"},
            named_refs={"bank-apple", "bank-miguel"}, own_names=set(),
        )

        self.assertEqual(pairs, [])

    def test_without_a_holder_name_the_same_name_on_both_legs_may_be_the_holder(self):
        out = txn("out", "ing", -5000, "2026-05-01", imported_description="J. SMITH JOHN")
        into = txn("in", "n26", 5000, "2026-05-02", imported_description="John Smith")

        pairs = _find_transfer_pairs(
            [out, into], {"ing", "n26"},
            named_refs={"bank-out", "bank-in"}, own_names=set(),
        )

        self.assertEqual(pairs, [(out, into)])

    def test_transactions_imported_before_names_were_recorded_pair_as_before(self):
        source = txn("source", "checking", -2500, "2026-05-01", imported_description="Someone")
        dest = txn("dest", "savings", 2500, "2026-05-01", imported_description="Someone Else")

        pairs = _find_transfer_pairs(
            [source, dest], {"checking", "savings"}, own_names={"david alves"},
        )

        self.assertEqual(pairs, [(source, dest)])

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
