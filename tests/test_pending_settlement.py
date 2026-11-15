"""A pending card payment that settles for a different amount.

pending_map is keyed on date|amount, so a booking whose amount changed on
settling (a tipped ride, a pre-authorisation) never found its pending copy. The
copy was then matched on financial_id, which updates everything but the amount,
so Actual kept the pending amount and the account balance drifted from the bank.
"""
import unittest
from types import SimpleNamespace

from app.sync import _find_pending_for_booking, _pending_slot


def txn(txn_id, financial_id):
    return SimpleNamespace(id=txn_id, financial_id=financial_id)


class FindPendingForBookingTest(unittest.TestCase):
    def test_finds_the_pending_copy_by_reference_when_the_amount_changed(self):
        pending = txn("uber", "ref-1")
        pending_map = {"2026-09-23|-23.60": "uber"}

        match = _find_pending_for_booking([pending], pending_map, "ref-1")

        self.assertEqual(match, ("2026-09-23|-23.60", pending))

    def test_ignores_a_transaction_that_is_no_longer_pending(self):
        """A booked transaction with the same reference is already settled."""
        booked = txn("uber", "ref-1")

        self.assertIsNone(_find_pending_for_booking([booked], {}, "ref-1"))

    def test_ignores_a_pending_copy_with_another_reference(self):
        pending = txn("uber", "ref-1")
        pending_map = {"2026-09-23|-23.60": "uber"}

        self.assertIsNone(_find_pending_for_booking([pending], pending_map, "ref-2"))

    def test_needs_a_reference(self):
        """Without one, two payments at the same merchant cannot be told apart."""
        pending = txn("uber", None)
        pending_map = {"2026-09-23|-23.60": "uber"}

        self.assertIsNone(_find_pending_for_booking([pending], pending_map, ""))
        self.assertIsNone(_find_pending_for_booking([pending], pending_map, None))


class PendingSlotTest(unittest.TestCase):
    """Two pending payments for the same amount on the same day (15 Nov 2026:
    two iPhones, two Amazon charges of -742.98) shared one date|amount key, so
    the second was skipped and never reached the budget."""

    def test_a_second_payment_with_another_reference_gets_its_own_slot(self):
        first = txn("a", "ref-1")
        pending_map = {"2026-11-15|-742.98": "a"}

        slot = _pending_slot([first], pending_map, "2026-11-15", "-742.98", "ref-2")

        self.assertEqual(slot, "2026-11-15|-742.98|ref-2")

    def test_the_same_payment_again_is_not_refiled(self):
        first = txn("a", "ref-1")
        pending_map = {"2026-11-15|-742.98": "a"}

        self.assertIsNone(_pending_slot([first], pending_map, "2026-11-15", "-742.98", "ref-1"))

    def test_the_second_payment_is_not_refiled_on_the_next_sync(self):
        first, second = txn("a", "ref-1"), txn("b", "ref-2")
        pending_map = {"2026-11-15|-742.98": "a", "2026-11-15|-742.98|ref-2": "b"}

        self.assertIsNone(_pending_slot([first, second], pending_map, "2026-11-15", "-742.98", "ref-2"))

    def test_without_references_it_keeps_the_old_date_amount_key(self):
        first = txn("a", None)
        self.assertEqual(_pending_slot([], {}, "2026-11-15", "-742.98", None), "2026-11-15|-742.98")
        self.assertIsNone(_pending_slot([first], {"2026-11-15|-742.98": "a"}, "2026-11-15", "-742.98", None))

    def test_each_booking_finds_its_own_pending_copy(self):
        first, second = txn("a", "ref-1"), txn("b", "ref-2")
        pending_map = {"2026-11-15|-742.98": "a", "2026-11-15|-742.98|ref-2": "b"}

        self.assertEqual(_find_pending_for_booking([first, second], pending_map, "ref-2"),
                         ("2026-11-15|-742.98|ref-2", second))
        self.assertEqual(_find_pending_for_booking([first, second], pending_map, "ref-1"),
                         ("2026-11-15|-742.98", first))


if __name__ == "__main__":
    unittest.main()
