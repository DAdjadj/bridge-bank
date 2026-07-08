"""Client for the bank-auth relay on api.bridgebank.app.

Safari (and some mobile in-app browsers) refuse the HTTPS -> HTTP hop from
bridgebank.app/callback to a local instance, which used to strand bank
authorisations. The relay closes that gap: start_auth registers a pending
state with the license API, the callback page encrypts the authorization
code with a per-attempt public key and posts it to the relay, and a local
poller thread claims the ciphertext, decrypts it with the private key that
never leaves this machine, and completes the auth without any browser
involvement. The browser redirect keeps working as a fast path.

Crypto per the frozen relay spec: P-256 ECDH (ephemeral key from the page),
HKDF-SHA256 (empty salt, info "bridge-bank-relay-v1"), AES-256-GCM,
base64url unpadded wire fields epk/iv/ct.
"""
import base64
import datetime
import logging
import threading
import time

import requests

from . import config, db

logger = logging.getLogger(__name__)

RELAY_BASE = "https://api.bridgebank.app"
POLL_FAST_SECONDS = 3
POLL_FAST_WINDOW = 120
POLL_SLOW_SECONDS = 15
POLL_LIFETIME_SECONDS = 30 * 60
HKDF_INFO = b"bridge-bank-relay-v1"

_poller_lock = threading.Lock()
_active_state_id = None


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def relay_enabled():
    raw = getattr(config, "RELAY_ENABLED", "true")
    return str(raw or "true").strip().lower() in {"1", "true", "yes", "on"}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_keypair():
    """Fresh P-256 keypair for one auth attempt. Returns (private_pem, pubkey_b64url)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return pem, _b64u(pub)


def decrypt_code(private_pem: str, epk: str, iv: str, ct: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv = load_pem_private_key(private_pem.encode(), password=None)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _b64u_decode(epk))
    shared = priv.exchange(ec.ECDH(), peer)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared)
    return AESGCM(key).decrypt(_b64u_decode(iv), _b64u_decode(ct), None).decode()


def _post(path: str, payload: dict, timeout: float = 3.0):
    r = requests.post(f"{RELAY_BASE}{path}", json=payload, timeout=timeout)
    try:
        data = r.json()
    except ValueError:
        data = {}
    return r, data


def _owner_payload():
    from . import licence
    return {
        "license_key": config.LICENCE_KEY,
        "machine_fingerprint": licence.get_machine_fingerprint(),
    }


def register(state_id: str, pubkey: str):
    """Best effort. Returns 'registered', 'disabled', 'denied' or 'unavailable'."""
    try:
        payload = _owner_payload()
        payload.update({"state_id": state_id, "pubkey": pubkey})
        r, data = _post("/auth-relay/register", payload)
        if data.get("status") == "disabled":
            return "disabled"
        if r.status_code == 200 and data.get("status") == "registered":
            return "registered"
        if r.status_code in (401, 403, 409):
            logger.warning("Relay register denied (%s): %s", r.status_code, data.get("error"))
            return "denied"
    except requests.RequestException as e:
        logger.info("Relay register unavailable: %s", e)
    return "unavailable"


def claim(state_id: str) -> dict:
    try:
        payload = _owner_payload()
        payload["state_id"] = state_id
        r, data = _post("/auth-relay/claim", payload)
        if r.status_code in (401, 403):
            return {"status": "denied", "error": data.get("error", "")}
        return data if data.get("status") else {"status": "unavailable"}
    except requests.RequestException:
        return {"status": "unavailable"}


def _flow_matches(state_id: str) -> bool:
    return db.get_setting("auth_flow_state_id") == state_id


def _flow_done() -> bool:
    return db.get_setting("auth_flow_status") == "done"


def _note(message: str):
    """Non-terminal relay-side note, surfaced softly by the progress card."""
    db.set_setting("auth_relay_note", message)


def _poll_loop(state_id: str, complete_cb):
    started_raw = db.get_setting("pending_session_started_at")
    try:
        started = datetime.datetime.fromisoformat(started_raw)
    except (TypeError, ValueError):
        started = _utcnow()
    deadline = started + datetime.timedelta(seconds=POLL_LIFETIME_SECONDS)
    registered = False
    reregister_attempted = False
    begun = time.monotonic()

    while _utcnow() < deadline:
        if not _flow_matches(state_id) or _flow_done():
            return
        if not registered:
            outcome = register(state_id, db.get_setting("pending_relay_pubkey"))
            if outcome == "registered":
                registered = True
                _note("")
            elif outcome in ("disabled", "denied"):
                _note("Automatic completion is unavailable. Use the link in the browser tab to finish.")
                return
            # 'unavailable' retries on the next pass
        if registered:
            result = claim(state_id)
            status = result.get("status")
            if status == "ready":
                try:
                    code = decrypt_code(
                        db.get_setting("pending_relay_privkey"),
                        result.get("epk", ""), result.get("iv", ""), result.get("ct", ""),
                    )
                except Exception as e:
                    logger.error("Relay payload could not be decrypted: %s", e)
                    _note("Automatic completion failed. Use the link in the browser tab to finish.")
                    return
                for attempt in range(3):
                    outcome, _message = complete_cb(code, state_id)
                    if outcome != "retryable":
                        return
                    time.sleep(5)
                _note("Automatic completion failed. Use the link in the browser tab to finish.")
                return
            if status == "cancelled":
                if db.compare_and_swap_setting("auth_flow_status", "pending", "in_progress"):
                    db.set_setting("auth_flow_outcome", "cancelled")
                    db.set_setting("auth_flow_message", "Bank connection was cancelled at the bank.")
                    db.set_setting("auth_flow_status", "done")
                return
            if status in ("expired", "disabled"):
                return
            if status == "denied":
                _note("Automatic completion is unavailable (license problem). Use the link in the browser tab to finish.")
                return
            if status == "unknown":
                if reregister_attempted:
                    return
                reregister_attempted = True
                registered = False
        elapsed = time.monotonic() - begun
        time.sleep(POLL_FAST_SECONDS if elapsed < POLL_FAST_WINDOW else POLL_SLOW_SECONDS)


def launch(complete_cb):
    """Start (or adopt) the poller for the current pending auth attempt."""
    global _active_state_id
    if not relay_enabled():
        return
    state_id = db.get_setting("auth_flow_state_id")
    if not state_id or _flow_done():
        return
    with _poller_lock:
        if _active_state_id == state_id:
            return
        _active_state_id = state_id

    def _run():
        global _active_state_id
        try:
            _poll_loop(state_id, complete_cb)
        finally:
            with _poller_lock:
                if _active_state_id == state_id:
                    _active_state_id = None

    threading.Thread(target=_run, daemon=True).start()


def revive(complete_cb):
    """On app start, resume polling if a fresh auth attempt survived a restart."""
    if not relay_enabled():
        return
    if db.get_setting("auth_flow_status") not in ("pending",):
        return
    started_raw = db.get_setting("pending_session_started_at")
    try:
        started = datetime.datetime.fromisoformat(started_raw)
    except (TypeError, ValueError):
        return
    if _utcnow() - started > datetime.timedelta(seconds=POLL_LIFETIME_SECONDS):
        return
    launch(complete_cb)
