"""Tests for syncs a person asked for: sent to the bank as the account holder.

PSD2 lets banks refuse more than four unattended requests a day per account,
and the scheduled syncs may need all four. A Sync now carries the person's IP
address and browser so the bank counts it as the holder being present. If a
bank refuses that, the sync must still work as a normal one.
"""
import datetime
import unittest
from unittest.mock import MagicMock, patch

import requests

from app import sync


def _resp(status, payload=None):
    r = MagicMock()
    r.status_code = status
    r.ok = status < 400
    r.json.return_value = payload if payload is not None else {"transactions": []}
    r.text = ""
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(response=r)
    return r


HOLDER = {"Psu-Ip-Address": "81.84.12.7", "Psu-User-Agent": "Mozilla/5.0"}


class HolderHeadersTest(unittest.TestCase):
    def test_needs_both_details_and_a_real_ip(self):
        self.assertEqual(sync.holder_headers("81.84.12.7", "Mozilla/5.0"), HOLDER)
        self.assertEqual(sync.holder_headers("", "Mozilla/5.0"), {})
        self.assertEqual(sync.holder_headers("81.84.12.7", ""), {})
        self.assertEqual(sync.holder_headers("not an ip", "Mozilla/5.0"), {})
        self.assertEqual(sync.holder_headers("::ffff:192.168.1.5", "x")["Psu-Ip-Address"],
                         "::ffff:192.168.1.5")
        self.assertEqual(len(sync.holder_headers("1.2.3.4", "a" * 400)["Psu-User-Agent"]), 255)


class HolderFetchTest(unittest.TestCase):
    def tearDown(self):
        sync._holder.headers = {}

    def _fetch(self, responses):
        with patch("app.sync.requests.get", side_effect=responses) as g, \
             patch("app.sync._make_headers", return_value={"Authorization": "Bearer t"}), \
             patch("app.sync.time.sleep"):
            sync._fetch_transactions("uid", datetime.date(2026, 10, 1))
        return [c.kwargs["headers"] for c in g.call_args_list]

    def test_scheduled_sync_sends_no_holder_details(self):
        sent = self._fetch([_resp(200)])
        self.assertNotIn("Psu-Ip-Address", sent[0])

    def test_sync_now_sends_holder_details(self):
        sync._holder.headers = HOLDER
        sent = self._fetch([_resp(200)])
        self.assertEqual(sent[0]["Psu-Ip-Address"], "81.84.12.7")
        self.assertEqual(sent[0]["Authorization"], "Bearer t")

    def test_refused_holder_request_falls_back_to_a_normal_one(self):
        sync._holder.headers = HOLDER
        sent = self._fetch([_resp(400, {"error": "WRONG_REQUEST_PARAMETERS"}), _resp(200)])
        self.assertEqual(len(sent), 2)
        self.assertIn("Psu-Ip-Address", sent[0])
        self.assertNotIn("Psu-Ip-Address", sent[1])

    def test_rate_limit_is_not_asked_again(self):
        sync._holder.headers = HOLDER
        with self.assertRaises(requests.HTTPError):
            self._fetch([_resp(429)] * 4)

    def test_run_clears_the_holder_afterwards(self):
        with patch("app.sync._run", side_effect=lambda *_: self.assertEqual(sync._holder_headers(), HOLDER)):
            sync.run(holder=HOLDER)
        self.assertEqual(sync._holder_headers(), {})


class SyncRouteTest(unittest.TestCase):
    def setUp(self):
        from app.web.server import app
        self.client = app.test_client()

    def _post(self, path, **kwargs):
        with patch("app.web.server.sync.run") as run, \
             patch("app.web.server.threading.Thread") as thread:
            thread.side_effect = lambda target, daemon: MagicMock(start=target)
            self.client.post(path, **kwargs)
        return run.call_args

    def test_bridge_budget_passes_the_person(self):
        call = self._post("/sync/now", json={"psu_ip": "81.84.12.7", "psu_user_agent": "Mozilla/5.0"},
                          headers={"User-Agent": "node"})
        self.assertEqual(call.kwargs["holder"], HOLDER)

    def test_own_button_in_a_browser_counts(self):
        call = self._post("/sync/now", headers={"User-Agent": "Mozilla/5.0 Safari",
                                                "X-Forwarded-For": "81.84.12.7"})
        self.assertEqual(call.kwargs["holder"]["Psu-Ip-Address"], "81.84.12.7")

    def test_a_script_stays_unattended(self):
        call = self._post("/sync/now", headers={"User-Agent": "node"})
        self.assertEqual(call.kwargs["holder"], {})
