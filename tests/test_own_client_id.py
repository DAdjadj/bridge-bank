"""Bridge Bank signs its changes with its own device id.

actualpy takes its clock from the last synced message, device id included, so imports went out under the
id of whichever device wrote last (seen 19-20 Nov 2026: the iPhone app's id on the 6-hourly imports).
See app.sync._patch_own_client_id.
"""
import os
import tempfile
import unittest

from actual import Actual
from actual.protobuf_models import HULC_Client, SyncRequest

import app.sync as sync_mod


class OwnClientIdTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._file = sync_mod._CLIENT_ID_FILE
        sync_mod._CLIENT_ID_FILE = os.path.join(self._tmp.name, "actual-client-id")
        sync_mod._own_client_id_value = None
        self._prop = Actual.__dict__["_sync_client"]
        self._patched = sync_mod._own_client_id_patched
        sync_mod._own_client_id_patched = False
        sync_mod._patch_own_client_id()

    def tearDown(self):
        Actual._sync_client = self._prop
        sync_mod._own_client_id_patched = self._patched
        sync_mod._CLIENT_ID_FILE = self._file
        sync_mod._own_client_id_value = None
        self._tmp.cleanup()

    def _client_after_sync(self, last_timestamp):
        a = object.__new__(Actual)
        a._hulc_client = HULC_Client.from_timestamp(last_timestamp)  # what Actual.sync() leaves behind
        return a

    def test_changes_carry_bridge_banks_id_not_the_last_writers(self):
        phone = "942efe7281024428"
        a = self._client_after_sync(f"2026-11-20T10:33:08.033Z-0005-{phone}")
        req = SyncRequest({"fileId": "f", "groupId": "g"})
        ts = a._sync_client.timestamp()
        own = sync_mod._own_client_id()
        self.assertRegex(own, r"^[0-9a-f]{16}$")
        self.assertTrue(ts.endswith("-" + own), ts)
        self.assertNotIn(phone, ts)
        # Time keeps moving forward from the last synced message.
        self.assertGreaterEqual(ts[:24], "2026-11-20T10:33:08.033Z")
        req.set_null_timestamp(client_id=a._sync_client.client_id)
        self.assertTrue(req.since.endswith(own))

    def test_same_id_every_run(self):
        first = sync_mod._own_client_id()
        sync_mod._own_client_id_value = None  # a new process
        self.assertEqual(sync_mod._own_client_id(), first)
        with open(sync_mod._CLIENT_ID_FILE) as f:
            self.assertEqual(f.read().strip(), first)

    def test_patch_is_idempotent(self):
        sync_mod._patch_own_client_id()
        a = self._client_after_sync("2026-11-20T10:33:08.033Z-0005-9b1fd03bc5747662")
        self.assertEqual(a._sync_client.client_id, sync_mod._own_client_id())


if __name__ == "__main__":
    unittest.main()
