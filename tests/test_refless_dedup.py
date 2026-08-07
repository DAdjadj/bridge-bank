"""Dedup for bookings the bank gives us no entry_reference for.

Enable Banking leaves entry_reference empty for some banks (Openbank NL is the
reported case). imported_refs can only remember a booking that has a reference,
so without a fallback those accounts re-added the same transaction on every
sync, accumulating a duplicate every sync interval.
"""
import datetime
import unittest

from app.sync import _find_imported_duplicate


class FakeTransaction:
    def __init__(self, txn_id, amount, imported_description, date, is_child=0):
        self.id = txn_id
        self.amount = amount
        self.imported_description = imported_description
        self.is_child = is_child
        self.cleared = True
        self._date = date

    def get_date(self):
        return self._date


def txn(txn_id, amount, description, day, is_child=0):
    return FakeTransaction(txn_id, amount, description, datetime.date(2026, 8, day), is_child)


class FindImportedDuplicateTest(unittest.TestCase):
    def test_matches_previous_import_of_the_same_booking(self):
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4)]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 4), -12.50, "ALBERT HEIJN 1234"
        )

        self.assertIs(match, existing[0])

    def test_ignores_a_different_amount(self):
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4)]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 4), -13.50, "ALBERT HEIJN 1234"
        )

        self.assertIsNone(match)

    def test_ignores_the_same_amount_from_a_different_payee(self):
        """Two 12.50 payments on one day are not the same transaction."""
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4)]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 4), -12.50, "JUMBO 5678"
        )

        self.assertIsNone(match)

    def test_ignores_the_same_purchase_on_a_different_day(self):
        """The same coffee on Monday and on Tuesday is two coffees, not one."""
        existing = [txn("a", -250, "CAFE DE PIJP", 4)]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 5), -2.50, "CAFE DE PIJP"
        )

        self.assertIsNone(match)

    def test_a_repeated_purchase_on_one_day_claims_each_copy_once(self):
        """Two identical coffees already imported must not both match one copy."""
        existing = [
            txn("a", -250, "CAFE DE PIJP", 4),
            txn("b", -250, "CAFE DE PIJP", 4),
        ]
        claimed = set()

        first = _find_imported_duplicate(
            existing, claimed, datetime.date(2026, 8, 4), -2.50, "CAFE DE PIJP"
        )
        claimed.add(str(first.id))
        second = _find_imported_duplicate(
            existing, claimed, datetime.date(2026, 8, 4), -2.50, "CAFE DE PIJP"
        )

        self.assertIs(first, existing[0])
        self.assertIs(second, existing[1])

    def test_a_second_purchase_the_same_day_is_added_when_only_one_copy_exists(self):
        """The surplus booking finds nothing left to claim, so the sync adds it."""
        existing = [txn("a", -250, "CAFE DE PIJP", 4)]
        claimed = set()

        first = _find_imported_duplicate(
            existing, claimed, datetime.date(2026, 8, 4), -2.50, "CAFE DE PIJP"
        )
        claimed.add(str(first.id))
        second = _find_imported_duplicate(
            existing, claimed, datetime.date(2026, 8, 4), -2.50, "CAFE DE PIJP"
        )

        self.assertIs(first, existing[0])
        self.assertIsNone(second)

    def test_ignores_split_children(self):
        existing = [txn("child", -1250, "ALBERT HEIJN 1234", 4, is_child=1)]

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 4), -12.50, "ALBERT HEIJN 1234"
        )

        self.assertIsNone(match)

    def test_matches_when_rules_renamed_the_payee(self):
        """Rules rewrite the payee after import, so only imported_description is stable."""
        existing = [txn("a", -1250, "ALBERT HEIJN 1234", 4)]
        existing[0].payee = "Groceries"

        match = _find_imported_duplicate(
            existing, set(), datetime.date(2026, 8, 4), -12.50, "ALBERT HEIJN 1234"
        )

        self.assertIs(match, existing[0])

    def test_tolerates_missing_imported_description(self):
        existing = [txn("a", -1250, None, 4)]

        self.assertIsNone(
            _find_imported_duplicate(
                existing, set(), datetime.date(2026, 8, 4), -12.50, "ALBERT HEIJN 1234"
            )
        )
        self.assertIs(
            _find_imported_duplicate(
                existing, set(), datetime.date(2026, 8, 4), -12.50, ""
            ),
            existing[0],
        )


if __name__ == "__main__":
    unittest.main()
