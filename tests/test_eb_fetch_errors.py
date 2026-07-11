"""Tests for Enable Banking fetch error classification and retries.

Only 401/403 should send users to re-authorise. Other bank errors must show
the real status and error code on the Status page (support diagnoses from a
screenshot), rate limits and 5xx must retry, and network errors must not
masquerade as auth problems.
"""
import unittest
from unittest.mock import patch, MagicMock

import requests

from app.sync import _fetch_failure_message, _eb_error_snippet, _fetch_transactions


def _http_error(status, body=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    if body is not None:
        resp.json.return_value = body
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = text
    err = requests.HTTPError(response=resp)
    return err


class FetchFailureMessageTest(unittest.TestCase):
    def test_401_and_403_ask_for_reauth(self):
        for status in (401, 403):
            msg = _fetch_failure_message("ING (NL) → ING Prive", _http_error(status))
            self.assertIn("session has expired", msg)
            self.assertIn("Re-authorise", msg)

    def test_429_does_not_ask_for_reauth(self):
        msg = _fetch_failure_message("ING (NL) → ING Prive", _http_error(429))
        self.assertIn("rate-limiting", msg)
        self.assertNotIn("Re-authorise", msg)

    def test_other_http_errors_surface_status_and_code(self):
        msg = _fetch_failure_message(
            "ING (NL) → ING Prive",
            _http_error(422, body={"message": "Session status is not authorized"}))
        self.assertIn("error 422", msg)
        self.assertIn("Session status is not authorized", msg)
        self.assertIn("send your logs", msg)

    def test_network_error_does_not_blame_the_session(self):
        msg = _fetch_failure_message("ING (NL) → ING Prive", requests.ConnectionError("boom"))
        self.assertIn("Could not reach your bank's API", msg)
        self.assertIn("retry on the next scheduled sync", msg)
        self.assertNotIn("Re-authorise", msg)

    def test_snippet_key_cascade_and_truncation(self):
        resp = MagicMock()
        resp.status_code = 422
        resp.json.return_value = {"detail": "x" * 500}
        self.assertEqual(len(_eb_error_snippet(resp)), 2 + 160)
        resp.json.return_value = {"code": "SESSION_EXPIRED", "detail": "long text"}
        self.assertEqual(_eb_error_snippet(resp), ": SESSION_EXPIRED")
        resp.json.side_effect = ValueError()
        self.assertEqual(_eb_error_snippet(resp), "")


class FetchRetryTest(unittest.TestCase):
    def _resp(self, status, payload=None):
        r = MagicMock()
        r.status_code = status
        r.ok = status < 400
        r.json.return_value = payload if payload is not None else {"transactions": []}
        r.text = ""
        return r

    def test_5xx_is_retried_then_succeeds(self):
        import datetime
        responses = [self._resp(502), self._resp(503), self._resp(200, {"transactions": [{"x": 1}]})]
        with patch("app.sync.requests.get", side_effect=responses) as g, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            txns = _fetch_transactions("uid", datetime.date(2026, 1, 1))
        self.assertEqual(len(txns), 1)
        self.assertEqual(g.call_count, 3)

    def test_429_still_retried(self):
        import datetime
        responses = [self._resp(429), self._resp(200)]
        with patch("app.sync.requests.get", side_effect=responses) as g, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            _fetch_transactions("uid", datetime.date(2026, 1, 1))
        self.assertEqual(g.call_count, 2)

    def test_persistent_5xx_raises_after_4_attempts(self):
        import datetime
        resp = self._resp(502)
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
        with patch("app.sync.requests.get", return_value=resp) as g, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            with self.assertRaises(requests.HTTPError):
                _fetch_transactions("uid", datetime.date(2026, 1, 1))
        self.assertEqual(g.call_count, 4)


class HistoryWindowTest(unittest.TestCase):
    """Unattended fetches must survive banks' post-SCA history limits."""

    def _resp(self, status, payload=None, text=""):
        r = MagicMock()
        r.status_code = status
        r.ok = status < 400
        r.json.return_value = payload if payload is not None else {"transactions": []}
        r.text = text
        if status >= 400:
            r.raise_for_status.side_effect = requests.HTTPError(response=r)
        return r

    def test_strategy_longest_is_requested(self):
        import datetime
        with patch("app.sync.requests.get", return_value=self._resp(200)) as g, \
             patch("app.sync._make_headers", return_value={}):
            _fetch_transactions("uid", datetime.date(2026, 1, 1))
        params = g.call_args.kwargs["params"]
        self.assertEqual(params.get("strategy"), "longest")

    def test_strategy_rejection_falls_back_to_plain_request(self):
        import datetime
        rejected = self._resp(422, text='{"error": "WRONG_REQUEST_PARAMETERS", "message": "strategy"}')
        ok = self._resp(200, {"transactions": [{"x": 1}]})
        with patch("app.sync.requests.get", side_effect=[rejected, ok]) as g, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            txns = _fetch_transactions("uid", datetime.date(2026, 1, 1))
        self.assertEqual(len(txns), 1)
        self.assertNotIn("strategy", g.call_args.kwargs["params"])

    def test_wrong_transactions_period_retries_with_clamped_window(self):
        import datetime
        refused = self._resp(422, text='{"error": "WRONG_TRANSACTIONS_PERIOD", "message": "Wrong transactions period requested"}')
        ok = self._resp(200)
        old_start = datetime.date.today() - datetime.timedelta(days=300)
        with patch("app.sync.requests.get", side_effect=[refused, ok]) as g, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            _fetch_transactions("uid", old_start)
        retried_from = datetime.date.fromisoformat(g.call_args.kwargs["params"]["date_from"])
        self.assertGreaterEqual(retried_from, datetime.date.today() - datetime.timedelta(days=89))

    def test_recent_window_does_not_retry_on_period_error(self):
        import datetime
        refused = self._resp(422, text='{"error": "WRONG_TRANSACTIONS_PERIOD"}')
        with patch("app.sync.requests.get", return_value=refused), \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync.time.sleep"):
            with self.assertRaises(requests.HTTPError):
                _fetch_transactions("uid", datetime.date.today() - datetime.timedelta(days=10))


if __name__ == "__main__":
    unittest.main()
