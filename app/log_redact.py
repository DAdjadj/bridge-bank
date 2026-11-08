"""Strip personal and secret data from log text before it leaves the install.

The Status page's Download logs button returns this, and customers send that
file to support. Old lines stay in bridge-bank.log (and .log.1) after an
update, so this has to catch what earlier versions logged too: account and
transaction objects as JSON or as Python dicts, nested or not.

No Flask here, so the test runs without it.
"""
import re

# Lines that carried a bank's account objects or a whole transaction.
_BLOB_LINES = re.compile(r"(Account picker data:|Skipping transaction: [^|\n]*\|).*")
# Any dict or list on a line that has an account or transaction key in it,
# in either quote style, up to the end of the line (nesting can't cut it short).
_ACCOUNT_BLOB = re.compile(r"""[\[{][^\n]*?["']account_id["']\s*:[^\n]*""")
_TRANSACTION_BLOB = re.compile(
    r"""[\[{][^\n]*?["'](?:transaction_id|entry_reference|transaction_amount|creditor_account|debtor_account)["']\s*:[^\n]*""")


def sanitize_logs(text):
    # Mask IBANs (2 letter country + 2 digits + up to 30 chars)
    text = re.sub(r'\b([A-Z]{2}\d{2})\w{4,}(\w{4})\b', r'\1****\2', text)
    # Mask email addresses
    text = re.sub(r'\b(\w{2})\w*(@\w+\.\w+)', r'\1***\2', text)
    # Remove account and transaction objects from Enable Banking
    text = _BLOB_LINES.sub(r"\1 [redacted]", text)
    text = _ACCOUNT_BLOB.sub("[account data redacted]", text)
    text = _TRANSACTION_BLOB.sub("[transaction data redacted]", text)
    # Mask OAuth query params: the access log records GET /callback?code=...&state=...
    # and these logs get emailed to support, so the single-use code must not survive here.
    text = re.sub(r'([?&](?:code|state)=)[^&\s"]+', r'\1[redacted]', text)
    return text
