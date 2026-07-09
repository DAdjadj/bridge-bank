"""Tests for the tri-state auth completion guard and the relay client.

The browser /callback and the relay poller can both deliver the same
single-use authorization code. _complete_auth_from_code must exchange it at
most once, keep transient failures retryable, and route the losing entrant
by the recorded outcome instead of surfacing a false error.
"""
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import db as appdb

_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
appdb.DB_PATH = _tmpdb.name

from app import relay
from app.web import server


def _reset_flow(state_id="11111111-2222-4333-8444-555555555555"):
    with appdb._conn() as conn:
        appdb._ensure_tables(conn)
        conn.execute("DELETE FROM settings")
        conn.execute("DELETE FROM bank_accounts")
        conn.commit()
    appdb.set_setting("pending_session_state", state_id)
    appdb.set_setting("auth_flow_state_id", state_id)
    appdb.set_setting("auth_flow_status", "pending")
    return state_id


def _one_account_result():
    return {"session_id": "sess-1", "accounts": [{"uid": "acc-1"}], "valid_until": "2027-01-01"}


def _two_account_result():
    return {"session_id": "sess-2", "accounts": [{"uid": "a"}, {"uid": "b"}], "valid_until": "2027-01-01"}


class CompareAndSwapTest(unittest.TestCase):
    def test_swap_only_from_expected_value(self):
        appdb.set_setting("k", "pending")
        self.assertTrue(appdb.compare_and_swap_setting("k", "pending", "in_progress"))
        self.assertFalse(appdb.compare_and_swap_setting("k", "pending", "in_progress"))
        self.assertEqual(appdb.get_setting("k"), "in_progress")

    def test_missing_row_counts_as_empty(self):
        with appdb._conn() as conn:
            conn.execute("DELETE FROM settings WHERE key='fresh'")
            conn.commit()
        self.assertTrue(appdb.compare_and_swap_setting("fresh", "", "x"))
        self.assertEqual(appdb.get_setting("fresh"), "x")


class CompleteAuthTest(unittest.TestCase):
    def setUp(self):
        self.state = _reset_flow()

    def test_single_account_success(self):
        with patch("app.enablebanking.complete_auth", return_value=_one_account_result()) as ca, \
             patch.object(server, "_save_bank_account") as save:
            outcome, _ = server._complete_auth_from_code("code-1", self.state, source="web")
        self.assertEqual(outcome, "success")
        ca.assert_called_once()
        save.assert_called_once()
        self.assertEqual(appdb.get_setting("auth_flow_status"), "done")

    def test_second_delivery_is_routed_not_reexchanged(self):
        with patch("app.enablebanking.complete_auth", return_value=_one_account_result()) as ca, \
             patch.object(server, "_save_bank_account"):
            first, _ = server._complete_auth_from_code("code-1", self.state, source="relay")
            second, _ = server._complete_auth_from_code("code-1", self.state, source="web")
        self.assertEqual(first, "success")
        self.assertEqual(second, "success")
        ca.assert_called_once()  # the code was exchanged exactly once

    def test_transient_exchange_failure_is_retryable(self):
        with patch("app.enablebanking.complete_auth", side_effect=[RuntimeError("EB 502"), _one_account_result()]) as ca, \
             patch.object(server, "_save_bank_account"):
            first, msg = server._complete_auth_from_code("code-1", self.state, source="relay")
            self.assertEqual(first, "retryable")
            self.assertEqual(appdb.get_setting("auth_flow_status"), "pending")
            second, _ = server._complete_auth_from_code("code-1", self.state, source="relay")
        self.assertEqual(second, "success")
        self.assertEqual(ca.call_count, 2)

    def test_failure_after_exchange_is_terminal_with_real_error(self):
        with patch("app.enablebanking.complete_auth", return_value=_one_account_result()), \
             patch.object(server, "_save_bank_account", side_effect=ValueError("Bank slot limit reached")):
            first, msg = server._complete_auth_from_code("code-1", self.state, source="web")
        self.assertEqual(first, "error")
        self.assertIn("slot limit", msg)
        # a late second delivery must NOT show success, and must not re-exchange
        with patch("app.enablebanking.complete_auth") as ca:
            second, msg2 = server._complete_auth_from_code("code-1", self.state, source="relay")
        self.assertEqual(second, "error")
        self.assertIn("slot limit", msg2)
        ca.assert_not_called()

    def test_stale_state_rejected(self):
        outcome, _ = server._complete_auth_from_code("code-1", "99999999-8888-4777-a666-555555555555", source="web")
        self.assertEqual(outcome, "stale")

    def test_legacy_attempt_without_flow_id_is_adopted(self):
        # An auth started on the previous app version has pending_session_state
        # but no auth_flow_* keys; the update must not strand it.
        appdb.set_setting("auth_flow_state_id", "")
        appdb.set_setting("auth_flow_status", "")
        with patch("app.enablebanking.complete_auth", return_value=_one_account_result()), \
             patch.object(server, "_save_bank_account"):
            outcome, _ = server._complete_auth_from_code("code-1", self.state, source="web")
        self.assertEqual(outcome, "success")

    def test_concurrent_legacy_adoption_exchanges_once(self):
        """Two simultaneous deliveries of a legacy (pre-update) attempt must not
        both adopt it and double-exchange the code."""
        import time as _time
        appdb.set_setting("auth_flow_state_id", "")
        appdb.set_setting("auth_flow_status", "")
        calls = []

        def slow_exchange(code, state):
            calls.append(code)
            _time.sleep(0.2)
            return _one_account_result()

        results = []
        with patch("app.enablebanking.complete_auth", side_effect=slow_exchange), \
             patch.object(server, "_save_bank_account"):
            threads = [threading.Thread(target=lambda: results.append(
                server._complete_auth_from_code("code-1", self.state, source="race")))
                for _ in range(2)]
            for t in threads: t.start()
            for t in threads: t.join()
        self.assertEqual(len(calls), 1)

    def test_callback_cancel_requires_matching_state(self):
        """A stray /callback?error=x hit must not cancel a live auth attempt."""
        client = server.app.test_client()
        client.get("/callback?error=access_denied")
        self.assertEqual(appdb.get_setting("auth_flow_status"), "pending")
        # with the matching state it does cancel
        client.get("/callback?error=access_denied&state=bridge-bank-auth2|http://x|" + self.state)
        self.assertEqual(appdb.get_setting("auth_flow_status"), "done")
        self.assertEqual(appdb.get_setting("auth_flow_outcome"), "cancelled")

    def test_transient_marker_matches_gateway_errors(self):
        from app.sync import _is_transient_actual_error
        self.assertTrue(_is_transient_actual_error(RuntimeError(
            "Server error '502 Bad Gateway' for url 'https://x.pikapod.net/sync/sync'")))
        self.assertTrue(_is_transient_actual_error(RuntimeError("503 Service Unavailable")))
        self.assertFalse(_is_transient_actual_error(RuntimeError("401 Unauthorized")))

    def test_log_sanitizer_masks_oauth_params(self):
        line = 'GET /callback?code=SECRET-CODE&state=bridge-bank-auth2%7Chttp HTTP/1.1" 302'
        out = server._sanitize_logs(line)
        self.assertNotIn("SECRET-CODE", out)
        self.assertIn("code=[redacted]", out)

    def test_multiple_accounts_route_to_picker(self):
        with patch("app.enablebanking.complete_auth", return_value=_two_account_result()):
            outcome, _ = server._complete_auth_from_code("code-1", self.state, source="relay")
        self.assertEqual(outcome, "picker")
        self.assertTrue(appdb.get_setting("pending_auth_accounts"))

    def test_concurrent_deliveries_exchange_once(self):
        import time as _time
        calls = []

        def slow_exchange(code, state):
            calls.append(code)
            _time.sleep(0.2)
            return _one_account_result()

        results = []
        with patch("app.enablebanking.complete_auth", side_effect=slow_exchange), \
             patch.object(server, "_save_bank_account"):
            threads = [threading.Thread(target=lambda: results.append(
                server._complete_auth_from_code("code-1", self.state, source="race")))
                for _ in range(2)]
            for t in threads: t.start()
            for t in threads: t.join()
        self.assertEqual(len(calls), 1)
        outcomes = sorted(r[0] for r in results)
        self.assertIn("success", outcomes)
        self.assertIn(outcomes[0], ("in_progress", "success"))


class RelayCryptoTest(unittest.TestCase):
    def test_roundtrip_matches_webcrypto_recipe(self):
        """Encrypt exactly as the callback page does, decrypt with relay.decrypt_code."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os as _os

        priv_pem, pubkey_b64 = relay.generate_keypair()

        # page side
        instance_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), relay._b64u_decode(pubkey_b64))
        eph = ec.generate_private_key(ec.SECP256R1())
        shared = eph.exchange(ec.ECDH(), instance_pub)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"bridge-bank-relay-v1").derive(shared)
        iv = _os.urandom(12)
        ct = AESGCM(key).encrypt(iv, b"the-auth-code", None)
        epk = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

        code = relay.decrypt_code(priv_pem, relay._b64u(epk), relay._b64u(iv), relay._b64u(ct))
        self.assertEqual(code, "the-auth-code")

    def test_pubkey_is_base64url_unpadded(self):
        _, pubkey = relay.generate_keypair()
        self.assertNotIn("=", pubkey)
        self.assertNotIn("+", pubkey)
        self.assertNotIn("/", pubkey)
        self.assertEqual(len(relay._b64u_decode(pubkey)), 65)


class PollerTest(unittest.TestCase):
    def setUp(self):
        self.state = _reset_flow()
        import datetime as _dt
        appdb.set_setting("pending_session_started_at",
                          _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat())
        appdb.set_setting("pending_relay_pubkey", "AAAA")
        appdb.set_setting("pending_relay_privkey", "pem")
        self._speed = patch.multiple(relay, POLL_FAST_SECONDS=0.01, POLL_SLOW_SECONDS=0.01)
        self._speed.start()

    def tearDown(self):
        self._speed.stop()

    def _run_poller(self, cb=None):
        relay._poll_loop(self.state, cb or (lambda code, state: ("success", "")))

    def test_denied_register_stops_and_notes(self):
        with patch.object(relay, "register", return_value="denied"):
            self._run_poller()
        self.assertIn("unavailable", appdb.get_setting("auth_relay_note"))
        self.assertEqual(appdb.get_setting("auth_flow_status"), "pending")  # browser path stays viable

    def test_ready_claims_decrypts_and_completes(self):
        completions = []
        with patch.object(relay, "register", return_value="registered"), \
             patch.object(relay, "claim", return_value={"status": "ready", "ct": "x", "iv": "y", "epk": "z"}), \
             patch.object(relay, "decrypt_code", return_value="the-code"):
            self._run_poller(lambda code, state: (completions.append((code, state)) or ("success", "")))
        self.assertEqual(completions, [("the-code", self.state)])

    def test_cancelled_marks_flow_done(self):
        with patch.object(relay, "register", return_value="registered"), \
             patch.object(relay, "claim", return_value={"status": "cancelled", "error": "cancelled"}):
            self._run_poller()
        self.assertEqual(appdb.get_setting("auth_flow_status"), "done")
        self.assertEqual(appdb.get_setting("auth_flow_outcome"), "cancelled")

    def test_unknown_stops_after_two_reregisters(self):
        registers = []
        with patch.object(relay, "register", side_effect=lambda *a: (registers.append(1) or "registered")), \
             patch.object(relay, "claim", return_value={"status": "unknown"}):
            self._run_poller()
        self.assertEqual(len(registers), 3)  # initial + 2 re-registers

    def test_poller_waits_out_browser_exchange(self):
        """A racing browser exchange (in_progress) must not kill the poller."""
        outcomes = iter(["in_progress", "in_progress", "success"])
        calls = []
        with patch.object(relay, "register", return_value="registered"), \
             patch.object(relay, "claim", return_value={"status": "ready", "ct": "x", "iv": "y", "epk": "z"}), \
             patch.object(relay, "decrypt_code", return_value="the-code"), \
             patch.object(relay.time, "sleep"):
            self._run_poller(lambda code, state: (calls.append(1) or (next(outcomes), "")))
        self.assertEqual(len(calls), 3)

    def test_revive_resets_stranded_in_progress(self):
        """A crash mid-exchange leaves in_progress; revive must unblock it."""
        appdb.set_setting("auth_flow_status", "in_progress")
        launched = []
        with patch.object(relay, "launch", side_effect=lambda cb: launched.append(1)):
            relay.revive(lambda code, state: ("success", ""))
        self.assertEqual(appdb.get_setting("auth_flow_status"), "pending")
        self.assertEqual(len(launched), 1)

    def test_denied_includes_404_unknown_license(self):
        class R:
            status_code = 404
        with patch.object(relay, "_post", return_value=(R(), {"error": "Invalid license key"})):
            self.assertEqual(relay.register("s", "p"), "denied")
            self.assertEqual(relay.claim("s")["status"], "denied")

    def test_poller_exits_when_new_auth_starts(self):
        with patch.object(relay, "register", return_value="registered"), \
             patch.object(relay, "claim", side_effect=lambda s: (
                 appdb.set_setting("auth_flow_state_id", "someone-else") or {"status": "pending"})):
            self._run_poller()  # must return instead of looping forever

    def test_retryable_completion_is_retried_then_gives_up(self):
        attempts = []
        with patch.object(relay, "register", return_value="registered"), \
             patch.object(relay, "claim", return_value={"status": "ready", "ct": "x", "iv": "y", "epk": "z"}), \
             patch.object(relay, "decrypt_code", return_value="the-code"), \
             patch.object(relay.time, "sleep"):
            self._run_poller(lambda code, state: (attempts.append(1) or ("retryable", "eb down")))
        self.assertEqual(len(attempts), 5)
        self.assertIn("failed", appdb.get_setting("auth_relay_note"))


if __name__ == "__main__":
    unittest.main()
