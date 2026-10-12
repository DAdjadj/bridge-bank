"""Tests for the in-app "Update now" call to the bundled Watchtower.

nickfedor/watchtower 1.22 answers GET /v1/update with a 405 and only accepts
POST. The app used GET, so every in-app update silently fell through to the
helper-container fallback. These pin the POST call and the GET retry kept for
Watchtower builds that refuse POST.
"""
import tempfile
import unittest
from unittest import mock

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app.web import server


def _resp(status, text=""):
    r = mock.Mock()
    r.status_code = status
    r.text = text
    return r


class WatchtowerUpdateTest(unittest.TestCase):
    def setUp(self):
        with appdb._conn() as conn:
            appdb._ensure_tables(conn)
        appdb.set_setting("update_available", "1")
        self.client = server.app.test_client()

    def _run(self, post_resp, get_resp=None):
        with mock.patch("requests.post", return_value=post_resp) as post, \
             mock.patch("requests.get", return_value=get_resp) as get, \
             mock.patch("os.path.exists", return_value=False):
            res = self.client.post("/update/run")
        return res, post, get

    def test_posts_to_watchtower_and_accepts_async_202(self):
        res, post, get = self._run(_resp(202))
        self.assertEqual(res.get_json(), {"updating": True})
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], "http://bridge-bank-watchtower:8080/v1/update")
        self.assertEqual(post.call_args.kwargs["headers"], {"Authorization": "Bearer bridge-bank-update"})
        get.assert_not_called()
        self.assertEqual(appdb.get_setting("update_available"), "0")

    def test_retries_with_get_when_post_is_refused(self):
        res, post, get = self._run(_resp(405), _resp(200))
        self.assertEqual(res.get_json(), {"updating": True})
        get.assert_called_once()

    def test_falls_back_when_watchtower_rejects_the_call(self):
        res, _, get = self._run(_resp(401, "missing or invalid API Key"))
        get.assert_not_called()
        self.assertEqual(res.status_code, 400)
        self.assertEqual(appdb.get_setting("update_available"), "1")


if __name__ == "__main__":
    unittest.main()
