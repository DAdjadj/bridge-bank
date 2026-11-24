"""A payment added by hand is matched by the bank import instead of doubled.

The Bridge Budget iPhone app adds a payment the moment someone pays with Apple
Pay: same account and amount, the merchant as payee, today's date, not cleared,
no bank reference. Every existing transaction was excluded from actualpy's
fuzzy match and the other dedup paths only knew copies Bridge Bank imported
itself, so the bank import always added a second copy. See
app.sync._find_manual_entry.

These run the real sync loop against an in-memory Actual budget.
"""
import contextlib
import datetime
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sqlmodel import Session, SQLModel, create_engine
from actual.database import strong_reference_session
from actual.queries import create_account, create_transaction, get_transactions

from app import sync

ACCOUNT = {"id": 1, "actual_account": "Checking", "bank_name": "Test Bank",
           "bank_country": "PT", "start_sync_date": "2026-11-01"}


def bank_line(ref, amount, payee, day, status="BOOK"):
    return {
        "entry_reference": ref,
        "status": status,
        "booking_date": f"2026-11-{day:02d}",
        "transaction_amount": {"amount": str(abs(amount)), "currency": "EUR"},
        "credit_debit_indicator": "DBIT" if amount < 0 else "CRDT",
        "creditor": {"name": payee},
    }


class ManualEntryMatchTest(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        SQLModel.metadata.create_all(engine)
        self.session = strong_reference_session(Session(engine))
        self.account = create_account(self.session, "Checking")
        self.session.commit()
        self.state = {"accounts": {}}
        self.actual = SimpleNamespace(session=self.session, commit=self.session.commit)

        @contextlib.contextmanager
        def fake_client(label):
            yield self.actual

        patches = [
            patch.object(sync, "_actual_client", fake_client),
            patch.object(sync, "_get_session", return_value=(None, "uid")),
            patch.object(sync, "resolve_actual_account", return_value=self.account),
            patch.object(sync, "_load_ruleset_tolerant"),
            patch.object(sync, "_run_ruleset_tolerant"),
            patch.object(sync, "_run_rules_on_transfer_counterparts"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def add_by_hand(self, amount, payee, day, notes="", category="Groceries", reconciled=False):
        t = create_transaction(self.session, datetime.date(2026, 11, day), self.account, payee,
                               notes, category, amount=amount, cleared=False)
        if reconciled:
            t.cleared = True
            t.reconciled = 1
        self.session.commit()
        return t

    def sync(self, *lines):
        with patch.object(sync, "_fetch_transactions", return_value=list(lines)):
            ok, _, msg = sync._sync_account(dict(ACCOUNT), self.state)
        self.assertTrue(ok, msg)

    def transactions(self):
        return list(get_transactions(self.session, account=self.account))

    def test_hand_added_then_booked_is_one_transaction(self):
        self.add_by_hand(-12.50, "Pingo Doce", 20, notes="weekly shop")

        self.sync(bank_line("ref-1", -12.50, "PINGO DOCE LISBOA", 21))

        [t] = self.transactions()
        self.assertTrue(t.cleared)
        self.assertEqual(t.financial_id, "ref-1")
        self.assertEqual(t.imported_description, "PINGO DOCE LISBOA")
        self.assertEqual(t.payee.name, "Pingo Doce")
        self.assertEqual(t.category.name, "Groceries")
        self.assertEqual(t.notes, "weekly shop")
        self.assertEqual(t.get_date(), datetime.date(2026, 11, 20))

    def test_a_second_sync_does_not_add_it_again(self):
        self.add_by_hand(-12.50, "Pingo Doce", 20)
        line = bank_line("ref-1", -12.50, "PINGO DOCE LISBOA", 21)

        self.sync(line)
        self.sync(line)

        self.assertEqual(len(self.transactions()), 1)

    def test_hand_added_then_pending_then_booked_is_one_transaction(self):
        self.add_by_hand(-40.00, "Galp", 20)

        self.sync(bank_line("ref-1", -40.00, "GALP AREEIRO", 20, status="PDNG"))
        [t] = self.transactions()
        self.assertFalse(t.cleared)
        self.assertEqual(t.financial_id, "ref-1")

        self.sync(bank_line("ref-1", -40.00, "GALP AREEIRO", 21))
        [t] = self.transactions()
        self.assertTrue(t.cleared)
        self.assertEqual(t.payee.name, "Galp")
        self.assertEqual(self.state["accounts"]["1"]["pending_map"], {})

    def test_pending_that_books_for_another_amount_takes_the_booked_amount(self):
        """A fuel hold or a tip: the linked copy settles through pending_map as today."""
        self.add_by_hand(-40.00, "Galp", 20)

        self.sync(bank_line("ref-1", -40.00, "GALP AREEIRO", 20, status="PDNG"))
        self.sync(bank_line("ref-1", -32.17, "GALP AREEIRO", 21))

        [t] = self.transactions()
        self.assertEqual(t.amount, -3217)
        self.assertTrue(t.cleared)
        self.assertEqual(t.payee.name, "Galp")

    def test_two_same_payments_on_one_day_each_claim_one_copy(self):
        self.add_by_hand(-2.50, "Cafe", 20)
        self.add_by_hand(-2.50, "Cafe", 20)

        self.sync(bank_line("ref-1", -2.50, "CAFE CENTRAL", 20),
                  bank_line("ref-2", -2.50, "CAFE CENTRAL", 20))

        txns = self.transactions()
        self.assertEqual(len(txns), 2)
        self.assertEqual({t.financial_id for t in txns}, {"ref-1", "ref-2"})
        self.assertTrue(all(t.cleared for t in txns))

    def test_hand_added_five_days_away_is_not_matched(self):
        self.add_by_hand(-12.50, "Pingo Doce", 15)

        self.sync(bank_line("ref-1", -12.50, "PINGO DOCE LISBOA", 20))

        txns = self.transactions()
        self.assertEqual(len(txns), 2)
        hand = next(t for t in txns if t.get_date() == datetime.date(2026, 11, 15))
        self.assertIsNone(hand.financial_id)
        self.assertFalse(hand.cleared)

    def test_a_tie_between_two_different_candidates_is_not_matched(self):
        """Same amount, same distance, neither payee matches: we cannot tell which one it is."""
        self.add_by_hand(-9.90, "Lunch with Ana", 20)
        self.add_by_hand(-9.90, "Pharmacy", 20)

        self.sync(bank_line("ref-1", -9.90, "SUMUP *XPTO", 20))

        txns = self.transactions()
        self.assertEqual(len(txns), 3)
        self.assertEqual(sum(1 for t in txns if t.financial_id is None), 2)

    def test_the_same_payee_wins_over_a_closer_date(self):
        self.add_by_hand(-9.90, "Pharmacy", 20)
        self.add_by_hand(-9.90, "Farmácia Estácio", 18)

        self.sync(bank_line("ref-1", -9.90, "FARMACIA ESTACIO", 20))

        txns = self.transactions()
        self.assertEqual(len(txns), 2)
        matched = next(t for t in txns if t.financial_id == "ref-1")
        self.assertEqual(matched.payee.name, "Farmácia Estácio")

    def test_a_reconciled_hand_added_transaction_is_not_matched(self):
        self.add_by_hand(-12.50, "Pingo Doce", 20, reconciled=True)

        self.sync(bank_line("ref-1", -12.50, "PINGO DOCE LISBOA", 20))

        self.assertEqual(len(self.transactions()), 2)


class SamePayeeTest(unittest.TestCase):
    def test_ignores_case_and_accents_and_allows_containment(self):
        self.assertTrue(sync._same_payee("Pingo Doce", "PINGO DOCE LISBOA"))
        self.assertTrue(sync._same_payee("FARMACIA ESTACIO", "Farmácia Estácio"))

    def test_needs_whole_words(self):
        self.assertFalse(sync._same_payee("Cafe", "CAFETARIA"))

    def test_empty_never_matches(self):
        self.assertFalse(sync._same_payee("", "PINGO DOCE"))
        self.assertFalse(sync._same_payee(None, "PINGO DOCE"))


if __name__ == "__main__":
    unittest.main()
