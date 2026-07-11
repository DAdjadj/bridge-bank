import datetime
import unittest
from unittest.mock import patch

from app import sync


class FakeResponse:
    status_code = 200
    ok = True

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class EnableBankingPaginationTest(unittest.TestCase):
    def test_continuation_requests_keep_original_date_range(self):
        responses = [
            FakeResponse({
                "transactions": [{"entry_reference": "first"}],
                "continuation_key": "next-page",
            }),
            FakeResponse({
                "transactions": [{"entry_reference": "second"}],
                "continuation_key": None,
            }),
        ]
        calls = []

        def fake_get(url, headers, params, timeout):
            calls.append({
                "url": url,
                "headers": headers,
                "params": dict(params),
                "timeout": timeout,
            })
            return responses.pop(0)

        date_from = datetime.date(2026, 5, 1)
        date_to = datetime.date.today().isoformat()

        with (
            patch.object(sync, "_make_headers", return_value={"Authorization": "Bearer test"}),
            patch.object(sync.requests, "get", side_effect=fake_get),
        ):
            transactions = sync._fetch_transactions("account-1", date_from)

        self.assertEqual(
            transactions,
            [{"entry_reference": "first"}, {"entry_reference": "second"}],
        )
        self.assertEqual(calls[0]["params"], {
            "date_from": "2026-05-01",
            "date_to": date_to,
            "strategy": "longest",
        })
        self.assertEqual(calls[1]["params"], {
            "date_from": "2026-05-01",
            "date_to": date_to,
            "strategy": "longest",
            "continuation_key": "next-page",
        })


if __name__ == "__main__":
    unittest.main()
