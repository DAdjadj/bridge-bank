"""Tests for Enable Banking fetch error classification and retries.

Only 401/403 should send users to re-authorise. Other bank errors must show
the real status and error code on the Status page (support diagnoses from a
screenshot), rate limits and 5xx must retry, and network errors must not
masquerade as auth problems.
"""
import unittest
from unittest.mock import patch, MagicMock

import requests

from app.sync import (_fetch_failure_message, _eb_error_snippet, _fetch_transactions,
                      _eb_nested_detail, _eb_probe_detail_snippet)


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

    def test_bank_side_refusal_does_not_send_users_to_reconnect(self):
        # A non-401/403 refusal is the bank rejecting the request, so a fresh
        # SCA cannot clear it and must not be suggested.
        msg = _fetch_failure_message(
            "Openbank (NL) → Openbank",
            _http_error(400, body={"code": 400, "message": "Error interacting with ASPSP",
                                   "detail": {"message": "Invalid status value"},
                                   "error": "ASPSP_ERROR"}))
        self.assertNotIn("Re-authorise", msg)
        self.assertNotIn("re-authorise", msg.lower())
        self.assertIn("retry on the next scheduled sync", msg)

    def test_nested_bank_detail_reaches_the_message(self):
        # "ASPSP_ERROR" alone names Enable Banking's category, not the fault.
        msg = _fetch_failure_message(
            "Openbank (NL) → Openbank",
            _http_error(400, body={"code": 400, "message": "Error interacting with ASPSP",
                                   "detail": {"message": "Invalid status value"},
                                   "error": "ASPSP_ERROR"}))
        self.assertIn("ASPSP_ERROR", msg)
        self.assertIn("Invalid status value", msg)

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


class RevokedConsentTest(unittest.TestCase):
    """A consent the bank revoked arrives as a bare ASPSP_ERROR.

    Openbank NL answers the transactions endpoint with detail:null and only
    names the fault on /details, so the message the user sees identifies
    nothing. And unlike other ASPSP errors this one is cleared by reconnecting,
    so the "reconnecting will not clear it" wording is wrong for it.
    """

    OPENBANK_TRANSACTIONS = {"code": 400, "message": "Error interacting with ASPSP",
                             "error": "ASPSP_ERROR", "detail": None}
    OPENBANK_DETAILS = {"code": 400, "message": "Error interacting with ASPSP",
                        "detail": {"message": "Unauthorized, authentication failure",
                                   "error_name": "HttpException"},
                        "error": "ASPSP_ERROR"}

    def _probe_response(self, body):
        r = MagicMock()
        r.ok = False
        r.status_code = 400
        r.json.return_value = body
        return r

    def _message(self, account=None, newer_session=False, probe=None):
        with patch("app.sync.requests.get", return_value=probe) as get, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync._bank_has_newer_session", return_value=newer_session):
            msg = _fetch_failure_message(
                "Openbank (NL) → Openbank Betaal",
                _http_error(400, body=self.OPENBANK_TRANSACTIONS),
                account=account)
        return msg, get

    def test_null_detail_is_filled_in_from_the_details_endpoint(self):
        msg, get = self._message(account={"id": 1, "account_uid": "uid-a"},
                                 probe=self._probe_response(self.OPENBANK_DETAILS))
        self.assertIn("Unauthorized, authentication failure", msg)
        self.assertIn("/accounts/uid-a/details", get.call_args.args[0])

    def test_authentication_failure_asks_for_a_reconnection(self):
        msg, _ = self._message(account={"id": 1, "account_uid": "uid-a"},
                               probe=self._probe_response(self.OPENBANK_DETAILS))
        self.assertIn("Re-authorise", msg)
        self.assertNotIn("will not clear it", msg)

    def test_a_newer_session_at_the_bank_points_at_rebinding(self):
        # Re-authorising here would revoke the session the other account is
        # using, so the repair has to be the one that spends no SCA.
        msg, _ = self._message(account={"id": 1, "account_uid": "uid-a"},
                               newer_session=True,
                               probe=self._probe_response(self.OPENBANK_DETAILS))
        self.assertIn("Re-bind to the newest connection", msg)
        self.assertNotIn("Re-authorise", msg)

    def test_probe_is_skipped_when_the_bank_already_named_the_fault(self):
        with patch("app.sync.requests.get") as get, \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync._bank_has_newer_session", return_value=False):
            msg = _fetch_failure_message(
                "Openbank (NL) → Openbank",
                _http_error(400, body={"error": "ASPSP_ERROR",
                                       "detail": {"message": "Invalid status value"}}),
                account={"id": 1, "account_uid": "uid-a"})
        get.assert_not_called()
        self.assertIn("Invalid status value", msg)
        self.assertNotIn("Re-authorise", msg)

    def test_a_failing_probe_leaves_the_original_message_intact(self):
        with patch("app.sync.requests.get", side_effect=requests.ConnectionError("boom")), \
             patch("app.sync._make_headers", return_value={}), \
             patch("app.sync._bank_has_newer_session", return_value=False):
            msg = _fetch_failure_message(
                "Openbank (NL) → Openbank",
                _http_error(400, body=self.OPENBANK_TRANSACTIONS),
                account={"id": 1, "account_uid": "uid-a"})
        self.assertIn("ASPSP_ERROR", msg)
        self.assertIn("will not clear it", msg)

    def test_probe_stays_quiet_when_details_answers_normally(self):
        ok = MagicMock()
        ok.ok = True
        with patch("app.sync.requests.get", return_value=ok), \
             patch("app.sync._make_headers", return_value={}):
            self.assertEqual(_eb_probe_detail_snippet("uid-a"), "")

    def test_enable_bankings_own_session_complaint_is_not_treated_as_the_banks(self):
        # "Session status is not authorized" is Enable Banking talking about
        # its own session, and stays a bank-side fault report.
        with patch("app.sync.requests.get") as get, \
             patch("app.sync._make_headers", return_value={}):
            msg = _fetch_failure_message(
                "ING (NL) → ING Prive",
                _http_error(422, body={"message": "Session status is not authorized"}))
        get.assert_not_called()
        self.assertIn("send your logs", msg)
        self.assertNotIn("Re-authorise", msg)

    def test_nested_detail_reader_handles_every_shape(self):
        r = MagicMock()
        r.json.return_value = {"detail": {"message": "  Unauthorized  "}}
        self.assertEqual(_eb_nested_detail(r), "Unauthorized")
        r.json.return_value = {"detail": "plain text"}
        self.assertEqual(_eb_nested_detail(r), "plain text")
        r.json.return_value = {"detail": None}
        self.assertEqual(_eb_nested_detail(r), "")
        r.json.return_value = {"detail": {"error_name": "HttpException"}}
        self.assertEqual(_eb_nested_detail(r), "")
        r.json.side_effect = ValueError()
        self.assertEqual(_eb_nested_detail(r), "")
        self.assertEqual(_eb_nested_detail(None), "")


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
