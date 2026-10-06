"""Dedup for bookings whose entry_reference the bank changed after we imported them.

Banks sometimes renumber transactions: Bankinter PT sends a new reference on
every fetch, and a bank moving to a new Enable Banking connector (ING to API v4,
September 2026) may send new ones after a reconnect. Deduping on the reference
alone then re-imports everything still inside the fetch window.
"""
import datetime
import unittest

from app.sync import _find_imported_duplicate


class FakeTransaction:
    def __init__(self, txn_id, amount, imported_description, date, financial_id):
        self.id = txn_id
        self.amount = amount
        self.imported_description = imported_description
        self.financial_id = financial_id
        self.is_child = 0
        self.cleared = True
        self._date = date

    def get_date(self):
        return self._date


def txn(txn_id, amount, description, day, financial_id):
    return FakeTransaction(txn_id, amount, description, datetime.date(2026, 10, day), financial_id)


def find(existing, claimed, amount, description, live_refs, day=4):
    return _find_imported_duplicate(
        existing, claimed, datetime.date(2026, 10, day), amount, description, live_refs=live_refs
    )


class ChangedReferenceTest(unittest.TestCase):
    def test_matches_the_old_copy_when_its_reference_is_gone(self):
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4, "old-1")]

        match = find(existing, set(), -12.50, "ALBERT HEIJN 1234", live_refs={"new-1"})

        self.assertIs(match, existing[0])

    def test_never_matches_a_copy_whose_reference_is_still_sent(self):
        """A second identical purchase is new, not a renumbered first one."""
        existing = [txn("a", -250, "CAFE DE PIJP", 4, "ref-1")]

        match = find(existing, set(), -2.50, "CAFE DE PIJP", live_refs={"ref-1", "ref-2"})

        self.assertIsNone(match)

    def test_never_matches_a_transaction_we_did_not_import(self):
        """Manual entries and reference-less imports have no financial_id."""
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4, None)]

        match = find(existing, set(), -12.50, "ALBERT HEIJN 1234", live_refs={"new-1"})

        self.assertIsNone(match)

    def test_ignores_a_different_day(self):
        existing = [txn("a", -250, "CAFE DE PIJP", 4, "old-1")]

        match = find(existing, set(), -2.50, "CAFE DE PIJP", live_refs={"new-1"}, day=5)

        self.assertIsNone(match)

    def test_a_fully_renumbered_day_claims_each_copy_once_and_adds_the_surplus(self):
        """Two coffees imported, bank renumbers, and a third coffee appears."""
        existing = [
            txn("a", -250, "CAFE DE PIJP", 4, "old-1"),
            txn("b", -250, "CAFE DE PIJP", 4, "old-2"),
        ]
        live = {"new-1", "new-2", "new-3"}
        claimed = set()

        results = []
        for _ in range(3):
            match = find(existing, claimed, -2.50, "CAFE DE PIJP", live_refs=live)
            if match is not None:
                claimed.add(str(match.id))
            results.append(match)

        self.assertEqual(results[:2], existing)
        self.assertIsNone(results[2])

    def test_reference_less_lookup_is_unchanged(self):
        """Without live_refs, a copy with a financial_id still qualifies as before."""
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4, "ref-1")]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 10, 4), -12.50, "ALBERT HEIJN 1234"
        )

        self.assertIs(match, existing[0])


if __name__ == "__main__":
    unittest.main()
