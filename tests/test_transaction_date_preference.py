"""Per-bank choice between the booking date and the transaction date.

Banks that book late hand Enable Banking a booking date that is days after
the date their own app shows: at KBC (BE) a Friday evening payment carries a
transaction and value date of Friday and a booking date of Monday, so weekend
and late-evening payments arrive in Actual shifted forward. The booking date
stays the default because it never moves once a transaction is booked, and
both the pending_map keys and the reference-less duplicate match are built
from it. The per-account preference swaps the order for the banks that need
it. See app.sync._parse_date.
"""
import datetime
import tempfile
import unittest

from app import db as appdb
from app.sync import _parse_date


def kbc_booked():
    """A booked KBC payment made on the Friday and booked on the Monday."""
    return {
        "entry_reference": "2026080100123",
        "booking_date": "2026-08-03",
        "value_date": "2026-08-01",
        "transaction_date": "2026-08-01",
        "status": "BOOK",
    }


def kbc_pending():
    """The same payment while the bank still calls it pending: no booking date."""
    return {
        "entry_reference": "",
        "value_date": "2026-08-01",
        "transaction_date": "2026-08-01",
        "status": "PDNG",
    }


class ParseDateTest(unittest.TestCase):
    def test_booking_date_wins_by_default(self):
        self.assertEqual(_parse_date(kbc_booked()), datetime.date(2026, 8, 3))

    def test_transaction_date_wins_when_preferred(self):
        self.assertEqual(
            _parse_date(kbc_booked(), prefer_transaction_date=True),
            datetime.date(2026, 8, 1),
        )

    def test_preference_falls_back_to_the_value_date(self):
        txn = kbc_booked()
        del txn["transaction_date"]

        self.assertEqual(
            _parse_date(txn, prefer_transaction_date=True), datetime.date(2026, 8, 1)
        )

    def test_preference_falls_back_to_the_booking_date(self):
        """A bank that sends nothing but a booking date still gets a date."""
        txn = {"booking_date": "2026-08-03"}

        self.assertEqual(
            _parse_date(txn, prefer_transaction_date=True), datetime.date(2026, 8, 3)
        )

    def test_default_order_is_unchanged(self):
        txn = {"value_date": "2026-08-02", "transaction_date": "2026-08-01"}

        self.assertEqual(_parse_date(txn), datetime.date(2026, 8, 2))

    def test_an_empty_date_is_skipped_rather_than_parsed(self):
        txn = {"booking_date": "", "value_date": "", "transaction_date": "2026-08-01"}

        self.assertEqual(_parse_date(txn), datetime.date(2026, 8, 1))

    def test_a_timestamp_is_cut_back_to_its_date(self):
        txn = {"booking_date": "2026-08-03T22:14:07Z"}

        self.assertEqual(_parse_date(txn), datetime.date(2026, 8, 3))

    def test_no_date_at_all_raises(self):
        with self.assertRaises(ValueError):
            _parse_date({"entry_reference": "x"})


class PendingSettlesOnItsOwnDateTest(unittest.TestCase):
    """The pending_map key is f"{date}|{amount}", so the date decides whether a
    booking is recognised as the pending transaction it was imported as."""

    def test_the_default_moves_a_transaction_when_it_books(self):
        pending = _parse_date(kbc_pending())
        booked = _parse_date(kbc_booked())

        self.assertNotEqual(pending, booked)

    def test_the_preference_keeps_it_on_one_date(self):
        pending = _parse_date(kbc_pending(), prefer_transaction_date=True)
        booked = _parse_date(kbc_booked(), prefer_transaction_date=True)

        self.assertEqual(pending, booked)
        self.assertEqual(booked, datetime.date(2026, 8, 1))


class PreferenceColumnTest(unittest.TestCase):
    """The preference is stored per bank account, like skip_pending."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._previous_path = appdb.DB_PATH
        appdb.DB_PATH = tmp.name
        self.addCleanup(setattr, appdb, "DB_PATH", self._previous_path)

    def _add_account(self):
        return appdb.add_bank_account("sess", "uid", "KBC", "BE", "KBC")

    def test_accounts_do_not_prefer_the_transaction_date_by_default(self):
        account_id = self._add_account()

        self.assertEqual(appdb.get_bank_account(account_id)["prefer_transaction_date"], 0)

    def test_the_preference_can_be_turned_on_and_off(self):
        account_id = self._add_account()

        appdb.update_bank_account_field(account_id, "prefer_transaction_date", "1")
        self.assertEqual(appdb.get_bank_account(account_id)["prefer_transaction_date"], 1)

        appdb.update_bank_account_field(account_id, "prefer_transaction_date", "0")
        self.assertEqual(appdb.get_bank_account(account_id)["prefer_transaction_date"], 0)

    def test_an_older_database_gains_the_column(self):
        """Existing installs have a bank_accounts table without the column."""
        account_id = self._add_account()
        with appdb._conn() as conn:
            conn.execute("ALTER TABLE bank_accounts DROP COLUMN prefer_transaction_date")
            conn.commit()

        account = appdb.get_bank_account(account_id)

        self.assertEqual(account["prefer_transaction_date"], 0)


if __name__ == "__main__":
    unittest.main()
