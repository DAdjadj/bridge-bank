"""Tests for recovering a licence whose activations are all held by
installations that no longer exist.

`docker compose down -v` wipes the stored machine fingerprint, so the next
start registers as a new installation. Once every slot is taken by wiped
installs, the release-other-installations route can't help (this machine
holds no activation yet), so the setup page offers to release them and
activate in one step.
"""
import tempfile
import unittest
from unittest import mock

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app import licence
from app.web import server

KEY = "a0cf9519-acbc-4163-a111-14cd66ce26f6"


def _resp(status, data):
    r = mock.Mock()
    r.status_code = status
    return r, data


class ActivationLimitRecoveryTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
            conn.execute("DELETE FROM settings")
            conn.commit()
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()

    def test_limit_error_offers_release_and_keeps_the_key(self):
        limit = _resp(409, {"error": "Activation limit reached (2)", "valid": False, "limit_reached": True})
        with mock.patch.object(licence, "_post_json", return_value=limit) as post:
            page = self.client.post("/setup", data={"license_key": KEY}).get_data(as_text=True)
        self.assertNotIn("replace_others", post.call_args.args[1])
        self.assertIn("Release previous installations and activate here", page)
        self.assertIn(f'name="license_key" value="{KEY}"', page)

    def test_other_409s_do_not_offer_release(self):
        trial = _resp(409, {"error": "A free trial has already been used on this machine.", "valid": False})
        with mock.patch.object(licence, "_post_json", return_value=trial):
            page = self.client.post("/setup", data={"license_key": KEY}).get_data(as_text=True)
        self.assertIn("free trial has already been used", page)
        self.assertNotIn("Release previous installations", page)

    def test_release_sends_replace_others_and_continues_setup(self):
        ok = _resp(200, {"status": "activated", "valid": True, "removed_activations": 2, "removed_seats": 1})
        with mock.patch.object(licence, "_post_json", return_value=ok) as post, \
             mock.patch.object(server.config, "set") as config_set:
            resp = self.client.post("/setup", data={"license_key": KEY, "replace_others": "1"})
        self.assertIs(post.call_args.args[1].get("replace_others"), True)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(appdb.get_setting("licence_key"), KEY)
        config_set.assert_called_with("LICENCE_KEY", KEY)


if __name__ == "__main__":
    unittest.main()
