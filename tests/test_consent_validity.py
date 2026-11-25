"""Each bank's consent ceiling is respected when starting an authorisation.

Trade Republic allows 90 days, and asking for Bridge Bank's default 180 made
Enable Banking refuse /auth with a 422 and no visible reason (issue #26).
"""
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app import enablebanking as eb

DAY = 24 * 3600
TR_MAX = 7776000
TR_422 = {"message": "ASPSP does not support consent validity more than 7776000 seconds in the future",
          "error": "WRONG_REQUEST_PARAMETERS"}


def _resp(status, data):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = data
    r.text = str(data)
    r.raise_for_status.side_effect = None if status < 400 else Exception(f"{status} error")
    return r


def _seconds_ahead(valid_until):
    dt = datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return dt.timestamp() - time.time()


class ConsentSecondsTest(unittest.TestCase):
    def test_default_when_bank_publishes_nothing(self):
        self.assertEqual(eb.consent_seconds(None), 180 * DAY)
        self.assertEqual(eb.consent_seconds(0), 180 * DAY)

    def test_capped_under_a_lower_ceiling(self):
        self.assertLess(eb.consent_seconds(TR_MAX), TR_MAX)
        self.assertGreater(eb.consent_seconds(TR_MAX), 89 * DAY)

    def test_never_more_than_the_default(self):
        self.assertEqual(eb.consent_seconds(365 * DAY), 180 * DAY)


class StartAuthTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
            conn.execute("DELETE FROM settings")
            conn.commit()
        self._p = [patch.object(eb, "_make_headers", return_value={}),
                   patch("app.relay.relay_enabled", return_value=False)]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()

    def _aspsps(self, max_validity):
        return _resp(200, {"aspsps": [
            {"name": "Trade Republic", "country": "NL", "maximum_consent_validity": max_validity},
            {"name": "Trade Republic", "country": "DE", "maximum_consent_validity": 15552000}]})

    def test_trade_republic_asks_under_90_days(self):
        with patch.object(eb.requests, "get", return_value=self._aspsps(TR_MAX)), \
             patch.object(eb.requests, "post", return_value=_resp(200, {"url": "https://bank"})) as post:
            self.assertEqual(eb.start_auth("Trade Republic", "NL")["url"], "https://bank")
        sent = post.call_args.kwargs["json"]["access"]["valid_until"]
        self.assertLess(_seconds_ahead(sent), TR_MAX)
        self.assertEqual(appdb.get_setting("pending_session_valid_until"), sent)

    def test_422_naming_the_limit_retries_once_under_it(self):
        # Lookup unavailable: first ask is 180 days, the bank names its limit.
        with patch.object(eb.requests, "get", side_effect=Exception("down")), \
             patch.object(eb.requests, "post",
                          side_effect=[_resp(422, TR_422), _resp(200, {"url": "https://bank"})]) as post:
            self.assertEqual(eb.start_auth("Trade Republic", "NL")["url"], "https://bank")
        self.assertEqual(post.call_count, 2)
        retry = post.call_args_list[1].kwargs["json"]["access"]["valid_until"]
        self.assertLess(_seconds_ahead(retry), TR_MAX)
        self.assertEqual(appdb.get_setting("pending_session_valid_until"), retry)

    def test_other_refusals_show_enable_bankings_reason(self):
        err = {"message": "Wrong ASPSP name provided", "error": "WRONG_ASPSP_PROVIDED"}
        with patch.object(eb.requests, "get", return_value=self._aspsps(TR_MAX)), \
             patch.object(eb.requests, "post", return_value=_resp(422, err)) as post:
            with self.assertRaises(RuntimeError) as cm:
                eb.start_auth("Trade Republic", "NL")
        self.assertEqual(post.call_count, 1)
        self.assertIn("Wrong ASPSP name provided", str(cm.exception))
        self.assertIn("422", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
