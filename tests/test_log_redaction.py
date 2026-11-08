"""Download logs leaves no bank account or transaction data in the file.

Customers send the Status page's log download to support. Older versions
logged the bank's account objects (as JSON from the account picker, or as
Python dicts) and whole transactions, and those lines are still on disk in
bridge-bank.log after an update. app.log_redact must strip them whatever the
quoting or nesting. No Flask needed.
"""
import json
import unittest

from app.log_redact import sanitize_logs

ACCOUNTS = [
    {"account_id": {"iban": "NL91ABNA0417164300", "other": {"identification": "4111111111111111",
                                                         "scheme_name": "CPAN"}},
     "name": "Alex Doe", "details": "Joint checking", "product": "Gold card",
     "credit_limit": {"amount": "2500.00", "currency": "EUR"}, "uid": "a1b2c3-uid",
     "identification_hash": "hash-123", "bban": "ABNA0417164300"},
    {"account_id": {"iban": "PT50000201231234567890154"}, "name": "Alex Doe", "uid": "d4e5f6-uid"},
]
SECRETS = ("Alex Doe", "4111111111111111", "Gold card", "2500.00", "a1b2c3-uid", "hash-123",
           "ABNA0417164300", "d4e5f6-uid", "Joint checking")
PREFIX = "2026-11-01 07:00:00 INFO app.web.server: "


class LogRedactionTest(unittest.TestCase):
    def assertClean(self, out):
        for secret in SECRETS:
            self.assertNotIn(secret, out)

    def test_account_picker_line_as_json(self):
        out = sanitize_logs(PREFIX + "Account picker data: " + json.dumps(ACCOUNTS) + "\n")
        self.assertClean(out)
        self.assertIn("Account picker data: [redacted]", out)

    def test_account_objects_as_python_dicts(self):
        out = sanitize_logs(PREFIX + "Accounts: " + repr(ACCOUNTS) + "\n")
        self.assertClean(out)
        self.assertIn("[account data redacted]", out)

    def test_account_objects_as_json_anywhere(self):
        out = sanitize_logs(PREFIX + "Session reply " + json.dumps({"accounts": ACCOUNTS}) + "\n")
        self.assertClean(out)

    def test_skipped_transaction_line(self):
        txn = {"transaction_id": "tx-1", "creditor": {"name": "Alex Doe"},
               "remittance_information": ["Gold card payment"], "transaction_amount": {"amount": "2500.00"}}
        for blob in (repr(txn), json.dumps(txn)):
            with self.subTest(blob[:20]):
                out = sanitize_logs(PREFIX + "Skipping transaction: bad date | " + blob + "\n")
                self.assertClean(out)
                self.assertIn("Skipping transaction: bad date | [redacted]", out)

    def test_transaction_dict_elsewhere(self):
        txn = {"entry_reference": "ref-9", "debtor": {"name": "Alex Doe"}}
        out = sanitize_logs(PREFIX + "Odd row " + json.dumps(txn) + "\n")
        self.assertNotIn("Alex Doe", out)
        self.assertIn("[transaction data redacted]", out)

    def test_ordinary_lines_and_other_lines_survive(self):
        text = (PREFIX + "Account picker shown with 2 account(s)\n"
                + PREFIX + "Account picker data: " + json.dumps(ACCOUNTS) + "\n"
                + PREFIX + "Set skip_pending=True for account 42\n"
                + PREFIX + "Sync complete: 7 transactions\n")
        out = sanitize_logs(text)
        self.assertIn("Account picker shown with 2 account(s)", out)
        self.assertIn("Set skip_pending=True for account 42", out)
        self.assertIn("Sync complete: 7 transactions", out)
        self.assertEqual(len(out.splitlines()), 4)

    def test_existing_masks_still_apply(self):
        out = sanitize_logs('IBAN NL91ABNA0417164300 to alex@example.com GET /callback?code=SECRET&state=x HTTP/1.1"')
        self.assertIn("NL91****4300", out)
        self.assertNotIn("alex@example.com", out)
        self.assertNotIn("SECRET", out)


if __name__ == "__main__":
    unittest.main()
