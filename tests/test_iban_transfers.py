"""Tests for pairing transfers on account numbers and the IBAN-in-notes option.

When every account carries the holder's name, amount and date alone cannot
tell which account a transfer went to. Enable Banking sends the other side's
IBAN, and Bridge Bank knows each connected account's own IBAN, so a leg whose
other side is one of the customer's own accounts pairs with certainty.
"""
import datetime
import json
import tempfile
import unittest
from types import SimpleNamespace

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name
with appdb._conn() as _c:
    appdb._ensure_tables(_c)

import actual.database  # noqa: F401  (registers the Actual tables for the test budget)
from app import enablebanking, sync
from app.sync import (
    _counterparty_iban,
    _find_transfer_pairs,
    _iban_verdict,
    _notes_with_iban,
    _remember_counterparty_ibans,
)

ING = "NL91INGB0001234567"
OPENBANK = "ES9100730100510123456789"
REVOLUT = "LT123250012345678901"
PARTNER = "NL20RABO0123456789"
SHOP = "DE89370400440532013000"

OWN = {"ing": ING, "openbank": OPENBANK, "revolut": REVOLUT}


def txn(txn_id, account_id, amount, date, payee=""):
    obj = SimpleNamespace(
        id=txn_id, acct=account_id, amount=amount, financial_id=f"bank-{txn_id}",
        cleared=1, transferred_id=None, is_parent=0, is_child=0,
        starting_balance_flag=0, reconciled=0, imported_description=payee,
    )
    obj.get_date = lambda: datetime.date.fromisoformat(date)
    return obj


class IbanParsingTest(unittest.TestCase):
    def test_clean_iban_drops_spaces_and_case(self):
        self.assertEqual(enablebanking.clean_iban("nl91 ingb 0001 2345 67"), ING)

    def test_clean_iban_rejects_things_that_are_not_ibans(self):
        self.assertEqual(enablebanking.clean_iban("12345678"), "")
        self.assertEqual(enablebanking.clean_iban(None), "")
        self.assertEqual(enablebanking.clean_iban(""), "")

    def test_iban_of_reads_iban_and_other_scheme(self):
        self.assertEqual(enablebanking.iban_of({"iban": ING}), ING)
        self.assertEqual(enablebanking.iban_of(
            {"other": {"identification": OPENBANK, "scheme_name": "IBAN"}}), OPENBANK)
        self.assertEqual(enablebanking.iban_of(
            {"other": {"identification": "12345", "scheme_name": "BBAN"}}), "")
        self.assertEqual(enablebanking.iban_of(None), "")

    def test_account_iban_reads_session_account_shapes(self):
        self.assertEqual(enablebanking.account_iban({"account_id": {"iban": REVOLUT}}), REVOLUT)
        self.assertEqual(enablebanking.account_iban(
            {"account_id": {}, "all_account_ids": [{"identification": ING, "scheme_name": "IBAN"}]}), ING)
        self.assertEqual(enablebanking.account_iban({"uid": "x"}), "")

    def test_counterparty_iban_is_creditor_for_money_out_and_debtor_for_money_in(self):
        out = {"credit_debit_indicator": "DBIT", "creditor_account": {"iban": OPENBANK},
               "debtor_account": {"iban": REVOLUT}}
        into = {"credit_debit_indicator": "CRDT", "creditor_account": {"iban": REVOLUT},
                "debtor_account": {"iban": PARTNER}}
        self.assertEqual(_counterparty_iban(out), OPENBANK)
        self.assertEqual(_counterparty_iban(into), PARTNER)
        self.assertEqual(_counterparty_iban({"credit_debit_indicator": "DBIT"}), "")


class NotesWithIbanTest(unittest.TestCase):
    def test_appends_after_the_bank_text(self):
        self.assertEqual(_notes_with_iban("Savings top-up", OPENBANK),
                         f"Savings top-up IBAN: {OPENBANK}")

    def test_empty_notes_get_just_the_iban(self):
        self.assertEqual(_notes_with_iban("", OPENBANK), f"IBAN: {OPENBANK}")

    def test_no_iban_leaves_notes_alone(self):
        self.assertEqual(_notes_with_iban("Card payment", ""), "Card payment")

    def test_bank_text_that_already_has_it_is_left_alone(self):
        ing_text = "Naam: J Schuurbiers IBAN: NL91 INGB 0001 2345 67 Omschrijving: sparen"
        self.assertEqual(_notes_with_iban(ing_text, ING), ing_text)


class RememberCounterpartyIbansTest(unittest.TestCase):
    def test_keeps_recent_ones_and_drops_old_ones(self):
        today = datetime.date(2026, 10, 28)
        kept = {"old": [SHOP, "2026-05-01"], "recent": [ING, "2026-10-20"]}
        raw = [{"entry_reference": "new", "booking_date": "2026-10-28",
                "credit_debit_indicator": "DBIT", "creditor_account": {"iban": OPENBANK}},
               {"entry_reference": "card", "booking_date": "2026-10-28",
                "credit_debit_indicator": "DBIT", "creditor": {"name": "Spotify"}}]
        result = _remember_counterparty_ibans(kept, raw, today=today)
        self.assertEqual(result, {"recent": [ING, "2026-10-20"], "new": [OPENBANK, "2026-10-28"]})


class IbanVerdictTest(unittest.TestCase):
    def test_other_accounts_own_iban_confirms(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIs(_iban_verdict(out, into, {"bank-out": OPENBANK}, OWN), True)

    def test_a_different_own_account_rules_it_out(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIs(_iban_verdict(out, into, {"bank-out": ING}, OWN), False)

    def test_someone_elses_iban_says_nothing(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIsNone(_iban_verdict(out, into, {"bank-out": SHOP}, OWN))

    def test_no_numbers_say_nothing(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIsNone(_iban_verdict(out, into, {}, OWN))
        self.assertIsNone(_iban_verdict(out, into, {"bank-out": OPENBANK}, {}))


class IbanTransferPairingTest(unittest.TestCase):
    ACCOUNTS = {"ing", "openbank", "revolut"}

    def test_same_name_same_amount_goes_to_the_account_the_iban_names(self):
        # Two 100 inflows the same day, both from "Justin Schuurbiers": the
        # amount alone is ambiguous, the IBAN on the outflow is not.
        out = txn("out", "revolut", -10000, "2026-10-28", "Justin Schuurbiers")
        to_openbank = txn("ob", "openbank", 10000, "2026-10-28", "Justin Schuurbiers")
        to_ing = txn("ing", "ing", 10000, "2026-10-28", "Justin Schuurbiers")
        txns = [out, to_openbank, to_ing]

        self.assertEqual(_find_transfer_pairs(txns, self.ACCOUNTS), [])
        self.assertEqual(
            _find_transfer_pairs(txns, self.ACCOUNTS,
                                 counterparty_ibans={"bank-out": OPENBANK}, own_ibans=OWN),
            [(out, to_openbank)])

    def test_the_inflows_iban_can_confirm_too(self):
        out = txn("out", "revolut", -5000, "2026-10-27")
        to_openbank = txn("ob", "openbank", 5000, "2026-10-28")
        to_ing = txn("ing", "ing", 5000, "2026-10-28")
        pairs = _find_transfer_pairs([out, to_openbank, to_ing], self.ACCOUNTS,
                                     counterparty_ibans={"bank-ob": REVOLUT}, own_ibans=OWN)
        self.assertEqual(pairs, [(out, to_openbank)])

    def test_iban_confirms_even_when_the_names_differ(self):
        # A partner's account connected to the same Bridge Bank: different
        # name, so the name check alone refuses it.
        own = dict(OWN, partner=PARTNER)
        out = txn("out", "partner", -2500, "2026-10-28", "Partner Name")
        into = txn("in", "revolut", 2500, "2026-10-28", "Partner Name")
        named = {"bank-out", "bank-in"}
        accounts = self.ACCOUNTS | {"partner"}
        self.assertEqual(
            _find_transfer_pairs([out, into], accounts, named_refs=named,
                                 own_names={"justin schuurbiers"}), [])
        self.assertEqual(
            _find_transfer_pairs([out, into], accounts, named_refs=named,
                                 own_names={"justin schuurbiers"},
                                 counterparty_ibans={"bank-in": PARTNER}, own_ibans=own),
            [(out, into)])

    def test_iban_of_another_own_account_blocks_a_wrong_pair(self):
        # The money went to ING; the only same-amount inflow is on Openbank,
        # so it is something else.
        out = txn("out", "revolut", -7000, "2026-10-28")
        into = txn("in", "openbank", 7000, "2026-10-28")
        self.assertEqual(_find_transfer_pairs([out, into], self.ACCOUNTS), [(out, into)])
        self.assertEqual(
            _find_transfer_pairs([out, into], self.ACCOUNTS,
                                 counterparty_ibans={"bank-out": ING}, own_ibans=OWN), [])

    def test_without_iban_data_matching_works_as_before(self):
        out = txn("out", "revolut", -7000, "2026-10-28")
        into = txn("in", "openbank", 7000, "2026-10-29")
        self.assertEqual(
            _find_transfer_pairs([out, into], self.ACCOUNTS,
                                 counterparty_ibans={"bank-out": SHOP}, own_ibans=OWN),
            [(out, into)])

    def test_confirmed_pairs_still_need_the_date_window(self):
        out = txn("out", "revolut", -7000, "2026-10-01")
        into = txn("in", "openbank", 7000, "2026-10-28")
        self.assertEqual(
            _find_transfer_pairs([out, into], self.ACCOUNTS,
                                 counterparty_ibans={"bank-out": OPENBANK}, own_ibans=OWN), [])


class OwnIbanStorageTest(unittest.TestCase):
    def setUp(self):
        appdb.DB_PATH = _tmpdb.name
        with appdb._conn() as c:
            c.execute("DELETE FROM bank_accounts")
            c.execute("DELETE FROM settings")
            c.commit()

    def _add(self, uid):
        return appdb.add_bank_account(session_id="s1", account_uid=uid, bank_name="Revolut",
                                      bank_country="NL", actual_account=uid)

    def test_connected_rows_pick_up_their_iban(self):
        row_id = self._add("uid-revolut")
        sync.remember_account_ibans([
            {"uid": "uid-revolut", "account_id": {"iban": REVOLUT}},
            {"uid": "uid-not-picked", "account_id": {"iban": OPENBANK}},
        ])
        self.assertEqual(appdb.get_bank_account(row_id)["iban"], REVOLUT)
        # The account not picked yet waits; the finished one is not kept twice.
        self.assertEqual(json.loads(appdb.get_setting(sync.ACCOUNT_IBANS_SETTING)),
                         {"uid-not-picked": OPENBANK})

    def test_a_row_saved_after_the_auth_gets_its_iban_on_the_next_sync(self):
        sync.remember_account_ibans([{"uid": "uid-ob", "account_id": {"iban": OPENBANK}}])
        row_id = self._add("uid-ob")
        accounts = appdb.get_all_bank_accounts()
        sync.fill_own_ibans(accounts)
        self.assertEqual(appdb.get_bank_account(row_id)["iban"], OPENBANK)
        self.assertEqual(accounts[0]["iban"], OPENBANK)

    def test_bare_uids_from_a_session_read_change_nothing(self):
        row_id = self._add("uid-x")
        sync.remember_account_ibans([{"uid": "uid-x"}, "uid-y"])
        self.assertEqual(appdb.get_bank_account(row_id)["iban"], "")


if __name__ == "__main__":
    unittest.main()


class FullSyncTest(unittest.TestCase):
    """Imports Enable Banking-shaped data into a throwaway Actual budget, then
    links transfers, the way a scheduled sync does."""

    def setUp(self):
        import uuid
        from sqlmodel import Session, SQLModel, create_engine
        appdb.DB_PATH = _tmpdb.name
        with appdb._conn() as c:
            c.execute("DELETE FROM bank_accounts")
            c.execute("DELETE FROM settings")
            c.commit()
        from sqlalchemy.pool import StaticPool
        engine = create_engine("sqlite://", poolclass=StaticPool,
                               connect_args={"check_same_thread": False})
        SQLModel.metadata.create_all(engine)
        self.session = Session(engine)
        self.addCleanup(self.session.close)
        self.banks = {}
        for name, iban in (("Revolut", REVOLUT), ("Openbank", OPENBANK), ("ING", ING)):
            row_id = appdb.add_bank_account("sess", f"uid-{name}", name, "NL", name,
                                            start_sync_date="2026-10-01")
            appdb.update_bank_account_field(row_id, "iban", iban)
            self.banks[name] = appdb.get_bank_account(row_id)
        self.raw = {
            # Justin moves 100 from Revolut to Openbank, and the same day
            # 100 lands on ING from his savings elsewhere. All in his name.
            "uid-Revolut": [{
                "entry_reference": "rev-1", "booking_date": "2026-10-28",
                "credit_debit_indicator": "DBIT", "status": "BOOK",
                "transaction_amount": {"amount": "100.00", "currency": "EUR"},
                "creditor": {"name": "Justin Schuurbiers"},
                "creditor_account": {"iban": OPENBANK},
                "remittance_information": ["Savings top-up"],
            }, {
                "entry_reference": "rev-2", "booking_date": "2026-10-28",
                "credit_debit_indicator": "DBIT", "status": "BOOK",
                "transaction_amount": {"amount": "10.99", "currency": "EUR"},
                "creditor": {"name": "Spotify"},
                "remittance_information": ["Card payment"],
            }],
            "uid-Openbank": [{
                "entry_reference": "ob-1", "booking_date": "2026-10-28",
                "credit_debit_indicator": "CRDT", "status": "BOOK",
                "transaction_amount": {"amount": "100.00", "currency": "EUR"},
                "debtor": {"name": "Justin Schuurbiers"},
            }],
            "uid-ING": [{
                "entry_reference": "ing-1", "booking_date": "2026-10-28",
                "credit_debit_indicator": "CRDT", "status": "BOOK",
                "transaction_amount": {"amount": "100.00", "currency": "EUR"},
                "debtor": {"name": "Justin Schuurbiers"},
                "debtor_account": {"iban": "NL02ABNA0123456789"},
            }],
        }

    def _sync(self, iban_in_notes):
        import contextlib
        from unittest.mock import patch
        from actual.queries import get_transactions

        test = self

        class _Client:
            session = test.session

            def commit(self):
                test.session.commit()

        @contextlib.contextmanager
        def fake_client(_label):
            yield _Client()

        state = {}
        with patch.object(sync, "_actual_client", fake_client), \
             patch.object(sync, "_fetch_transactions", lambda uid, _d: self.raw[uid]), \
             patch.object(sync.config, "IBAN_IN_NOTES", "true" if iban_in_notes else "false", create=True), \
             patch.object(sync.config, "ACCOUNT_HOLDER_NAME", "Justin Schuurbiers"):
            accounts = appdb.get_all_bank_accounts()
            for a in accounts:
                ok, _, msg = sync._sync_account(a, state)
                self.assertTrue(ok, msg)
            counterparty_ibans = {ref: e[0] for s in state["accounts"].values()
                                  for ref, e in s["counterparty_ibans"].items()}
            linked = sync._auto_link_internal_transfers(_Client(), accounts, frozenset(),
                                                        counterparty_ibans)
            self.session.commit()
        txns = {t.financial_id: t for t in get_transactions(self.session)}
        return linked, txns

    def test_transfer_pairs_with_the_account_its_iban_names(self):
        linked, txns = self._sync(iban_in_notes=False)
        self.assertEqual(linked, 1)
        self.assertEqual(txns["rev-1"].transferred_id, txns["ob-1"].id)
        self.assertEqual(txns["ob-1"].transferred_id, txns["rev-1"].id)
        self.assertIsNone(txns["ing-1"].transferred_id)
        self.assertIsNone(txns["rev-2"].transferred_id)

    def test_notes_stay_as_they_were_with_the_option_off(self):
        _, txns = self._sync(iban_in_notes=False)
        self.assertEqual(txns["rev-1"].notes, "Savings top-up")
        self.assertIsNone(txns["ing-1"].notes or None)

    def test_notes_end_with_the_iban_with_the_option_on(self):
        _, txns = self._sync(iban_in_notes=True)
        self.assertEqual(txns["rev-1"].notes, f"Savings top-up IBAN: {OPENBANK}")
        self.assertEqual(txns["ing-1"].notes, "IBAN: NL02ABNA0123456789")
        self.assertEqual(txns["rev-2"].notes, "Card payment")


class OwnIbanOnTheWrongSideTest(unittest.TestCase):
    """A bank that puts the account's own IBAN where the other side belongs
    must not block a pair or put the account's own number in its notes."""

    def test_own_iban_is_not_the_counterparty(self):
        swapped = {"credit_debit_indicator": "DBIT", "creditor_account": {"iban": REVOLUT}}
        self.assertEqual(_counterparty_iban(swapped, REVOLUT), "")
        self.assertEqual(_counterparty_iban(swapped), REVOLUT)  # without knowing it, nothing to compare

    def test_own_iban_is_not_remembered(self):
        raw = [{"entry_reference": "x", "booking_date": "2026-10-28",
                "credit_debit_indicator": "DBIT", "creditor_account": {"iban": REVOLUT}}]
        self.assertEqual(_remember_counterparty_ibans({}, raw, today=datetime.date(2026, 10, 28),
                                                      own_iban=REVOLUT), {})

    def test_own_iban_on_a_leg_does_not_rule_the_pair_out(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIsNone(_iban_verdict(out, into, {"bank-out": REVOLUT}, OWN))
        self.assertEqual(
            _find_transfer_pairs([out, into], {"revolut", "openbank"},
                                 counterparty_ibans={"bank-out": REVOLUT}, own_ibans=OWN),
            [(out, into)])

    def test_the_other_leg_can_still_confirm(self):
        out = txn("out", "revolut", -100, "2026-10-28")
        into = txn("in", "openbank", 100, "2026-10-28")
        self.assertIs(_iban_verdict(out, into, {"bank-out": REVOLUT, "bank-in": REVOLUT}, OWN), True)


class SwappedFieldsFullSyncTest(FullSyncTest):
    """The full sync again, with a bank that swaps the fields on Revolut."""

    def setUp(self):
        super().setUp()
        self.raw["uid-Revolut"][0]["creditor_account"] = {"iban": REVOLUT}
        self.raw["uid-Revolut"][0]["debtor_account"] = {"iban": OPENBANK}
        # Openbank's leg names Revolut correctly, so the pair is still certain.
        self.raw["uid-Openbank"][0]["debtor_account"] = {"iban": REVOLUT}

    def test_transfer_pairs_with_the_account_its_iban_names(self):
        linked, txns = self._sync(iban_in_notes=False)
        self.assertEqual(linked, 1)
        self.assertEqual(txns["rev-1"].transferred_id, txns["ob-1"].id)

    def test_notes_stay_as_they_were_with_the_option_off(self):
        _, txns = self._sync(iban_in_notes=False)
        self.assertEqual(txns["rev-1"].notes, "Savings top-up")

    def test_notes_end_with_the_iban_with_the_option_on(self):
        _, txns = self._sync(iban_in_notes=True)
        self.assertEqual(txns["rev-1"].notes, "Savings top-up")  # its own number is not added
        self.assertEqual(txns["ob-1"].notes, f"IBAN: {REVOLUT}")
