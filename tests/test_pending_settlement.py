"""A pending card payment that settles for a different amount.

pending_map is keyed on date|amount, so a booking whose amount changed on
settling (a tipped ride, a pre-authorisation) never found its pending copy. The
copy was then matched on financial_id, which updates everything but the amount,
so Actual kept the pending amount and the account balance drifted from the bank.
"""
import unittest
from types import SimpleNamespace

from app.sync import _find_pending_for_booking


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


if __name__ == "__main__":
    unittest.main()
