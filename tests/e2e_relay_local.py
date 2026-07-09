"""Full-stack local E2E for the auth relay. NOT part of the unit suite.

Run manually:  python tests/e2e_relay_local.py
Requires: the license-api worker running locally (wrangler dev --local) on
127.0.0.1:8799, and node on PATH (plays the callback page's WebCrypto role).

Exercises the REAL components end to end: the Flask app in-process (routes,
poller, tri-state guard), the real Worker endpoints and D1 semantics, the
real Python decryption, and a mock Enable Banking that enforces single-use
authorization codes exactly like OAuth does.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RELAY = "http://127.0.0.1:8799"
MOCK_EB_PORT = 8798
NODE_ENC = os.path.join(tempfile.gettempdir(), "bb_encrypt_page.mjs")

# ---------------------------------------------------------------- app setup
from app import db as appdb
appdb.DB_PATH = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name

from app import config, licence, relay, enablebanking
config.CONFIG_FILE = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
licence.LICENCE_BASE = RELAY
relay.RELAY_BASE = RELAY
relay.POLL_FAST_SECONDS = 0.2
relay.POLL_SLOW_SECONDS = 0.2
enablebanking.EB_API = f"http://127.0.0.1:{MOCK_EB_PORT}"

config.LICENCE_KEY = None  # set after seeding
config.ACTUAL_URL = "http://127.0.0.1:9"   # fails instantly; sync path unused here
config.ACTUAL_PASSWORD = "x"
config.ACTUAL_SYNC_ID = "x"
config.ACTUAL_ACCOUNT = "Main"
config.EB_BANK_NAME = "Mock Bank"
config.EB_BANK_COUNTRY = "NL"

from app.web import server

# ------------------------------------------------------------- mock EB bank
from flask import Flask, request as freq, jsonify

mock_eb = Flask("mock_eb")
EB_STATE = {"auth_states": {}, "issued": {}, "used": [], "sessions_calls": 0, "accounts": [{"uid": "acc-1"}]}

@mock_eb.route("/auth", methods=["POST"])
def eb_auth():
    body = freq.get_json()
    state = body["state"]
    code = "code-" + os.urandom(6).hex()
    EB_STATE["auth_states"][state] = code
    EB_STATE["issued"][code] = state
    return jsonify({"url": f"https://mockbank.example/authorize?state={state}"})

@mock_eb.route("/sessions", methods=["POST"])
def eb_sessions():
    EB_STATE["sessions_calls"] += 1
    body = freq.get_json()
    code = body["code"]
    if code in EB_STATE["used"]:
        return jsonify({"detail": "authorization code already used"}), 400
    if code not in EB_STATE["issued"]:
        return jsonify({"detail": "unknown code"}), 400
    EB_STATE["used"].append(code)
    return jsonify({"session_id": "sess-" + code[-6:], "accounts": EB_STATE["accounts"]})

def start_mock_eb():
    t = threading.Thread(
        target=lambda: mock_eb.run(host="127.0.0.1", port=MOCK_EB_PORT, debug=False, use_reloader=False),
        daemon=True)
    t.start()
    import requests
    for _ in range(50):
        try:
            requests.post(f"http://127.0.0.1:{MOCK_EB_PORT}/auth", json={"state": "warmup"}, timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("mock EB did not start")

# ------------------------------------------------------------ node page sim
ENC_JS = r"""
const [pubkeyB64u, code] = process.argv.slice(2);
const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const subtle = globalThis.crypto.subtle;
const instancePub = await subtle.importKey('raw', b64uToBuf(pubkeyB64u), {name:'ECDH', namedCurve:'P-256'}, false, []);
const eph = await subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
const shared = await subtle.deriveBits({name:'ECDH', public: instancePub}, eph.privateKey, 256);
const hkdfKey = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
const aesKey = await subtle.deriveKey(
  {name:'HKDF', hash:'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode('bridge-bank-relay-v1')},
  hkdfKey, {name:'AES-GCM', length:256}, false, ['encrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await subtle.encrypt({name:'AES-GCM', iv}, aesKey, new TextEncoder().encode(code));
const epkRaw = await subtle.exportKey('raw', eph.publicKey);
console.log(JSON.stringify({epk: bufToB64u(epkRaw), iv: bufToB64u(iv), ct: bufToB64u(ct)}));
"""

def page_deliver(state_full, code):
    """Simulate the callback page: status -> encrypt -> complete (real HTTP + real WebCrypto)."""
    import requests
    state_id = state_full.split("|")[-1]
    st = requests.post(f"{RELAY}/auth-relay/status", json={"state_id": state_id}, timeout=5).json()
    if not st.get("pubkey"):
        return {"delivered": False, "status": st}
    out = subprocess.run(["node", NODE_ENC, st["pubkey"], code], capture_output=True, text=True, timeout=30)
    payload = json.loads(out.stdout)
    payload["state_id"] = state_id
    requests.post(f"{RELAY}/auth-relay/complete", json=payload, timeout=5)
    return {"delivered": True}

def page_cancel(state_full):
    import requests
    state_id = state_full.split("|")[-1]
    requests.post(f"{RELAY}/auth-relay/complete", json={"state_id": state_id, "error": "cancelled"}, timeout=5)

# ----------------------------------------------------------------- helpers
PASS, FAIL = [], []

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"  [{detail}]" if detail and not cond else ""))

def seed_license():
    import requests, uuid
    r = requests.post(f"{RELAY}/generate", json={"email": "e2e@example.com", "product": "bridge-bank", "skip_email": True},
                      headers={"X-Admin-Password": "testadmin", "Host": "api.bridgebank.app"}, timeout=10)
    key = (r.json() or {}).get("license_key")
    if not key:
        # email send fails locally and eats the key; fetch it from the licenses list
        r2 = requests.get(f"{RELAY}/licenses/bridge-bank", headers={"X-Admin-Password": "testadmin"}, timeout=10)
        rows = [x for x in r2.json() if x.get("email") == "e2e@example.com"]
        key = rows[-1]["license_key"]
    config.LICENCE_KEY = key
    fp = licence.get_machine_fingerprint()
    a = requests.post(f"{RELAY}/activate", json={"license_key": key, "machine_fingerprint": fp, "instance_name": "e2e"}, timeout=10)
    assert a.json().get("valid"), f"activation failed: {a.text}"
    print(f"license seeded: {key[:8]}... fp {fp[:8]}...")

def make_eb_pem():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    appdb.set_setting("eb_pem_content", pem)
    appdb.set_setting("eb_app_id", "e2e0e2e0-0000-4000-8000-000000000000")

def seed_bank_account():
    return appdb.add_bank_account(session_id="old-sess", account_uid="acc-1", bank_name="Mock Bank",
                                  bank_country="NL", actual_account="Main", session_expiry="2026-01-01")

def reset_flow():
    for k in ["auth_flow_state_id", "auth_flow_status", "auth_flow_outcome", "auth_flow_message",
              "auth_relay_note", "pending_session_state", "pending_relay_privkey", "pending_relay_pubkey",
              "pending_session_started_at", "pending_auth_session_id", "pending_auth_accounts",
              "pending_auth_valid_until", "pending_reauth_account_id"]:
        appdb.set_setting(k, "")

def start_reauth(client, account_id):
    r = client.post("/bank/reauthorise", data={"account_id": str(account_id),
                                               "bank_name": "Mock Bank", "bank_country": "NL"})
    assert r.status_code == 200, f"reauthorise returned {r.status_code}: {r.headers.get('Location')}"
    state_full = [s for s in EB_STATE["auth_states"] if s != "warmup"][-1]
    code = EB_STATE["auth_states"][state_full]
    return state_full, code

def wait_flow_done(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if appdb.get_setting("auth_flow_status") == "done":
            return True
        time.sleep(0.2)
    return False

# ---------------------------------------------------------------- scenarios
def scenario_relay_only(client, account_id):
    print("\n[1] Safari case: relay completes with NO browser redirect")
    reset_flow()
    state, code = start_reauth(client, account_id)
    check("state is v2", state.startswith("bridge-bank-auth2|"))
    d = page_deliver(state, code)
    check("page delivered ciphertext", d["delivered"])
    check("flow completed by poller", wait_flow_done())
    check("outcome success", appdb.get_setting("auth_flow_outcome") == "success")
    acct = appdb.get_bank_account(account_id)
    check("account session updated", acct["session_id"].startswith("sess-"))
    check("private key cleared", appdb.get_setting("pending_relay_privkey") == "")

def scenario_race(client, account_id):
    print("\n[2] Race: browser redirect AND relay deliver the same code")
    reset_flow()
    EB_STATE["sessions_calls"] = 0
    state, code = start_reauth(client, account_id)
    d = page_deliver(state, code)
    check("delivered", d["delivered"])
    # browser redirect arrives at the same time as the poller claims
    r = client.get(f"/callback?code={code}&state={state}")
    wait_flow_done()
    time.sleep(1.5)  # let any second exchange attempt happen
    exchanges = len([c for c in EB_STATE["used"] if c == code])
    check("code exchanged exactly once", exchanges == 1, f"used {exchanges}x, sessions_calls={EB_STATE['sessions_calls']}")
    check("outcome success", appdb.get_setting("auth_flow_outcome") == "success")
    check("browser routed to a success page (not error)", "/bank?error" not in (r.headers.get("Location") or ""))

def scenario_cancel(client, account_id):
    print("\n[3] Cancel at the bank via relay error")
    reset_flow()
    state, code = start_reauth(client, account_id)
    page_cancel(state)
    check("flow cancelled", wait_flow_done() and appdb.get_setting("auth_flow_outcome") == "cancelled")

def scenario_stray_cancel_ignored(client, account_id):
    print("\n[4] Stray /callback?error hit must NOT cancel a live attempt")
    reset_flow()
    state, code = start_reauth(client, account_id)
    client.get("/callback?error=denied")  # no state
    client.get("/callback?error=denied&state=bridge-bank-auth2|http://x|99999999-9999-4999-8999-999999999999")
    check("attempt still pending", appdb.get_setting("auth_flow_status") == "pending")
    d = page_deliver(state, code)
    check("still completes after stray hits", wait_flow_done() and appdb.get_setting("auth_flow_outcome") == "success")

def scenario_restart_revive(client, account_id):
    print("\n[5] App restart: code delivered while app was down, revive() claims it")
    reset_flow()
    state, code = start_reauth(client, account_id)
    # kill the poller by faking a restart: forget the in-memory poller state
    with relay._poller_lock:
        relay._active_state_id = "someone-else"   # make the running poller exit on next tick
    time.sleep(0.6)
    d = page_deliver(state, code)   # delivered while "down"
    check("delivered while down", d["delivered"])
    with relay._poller_lock:
        relay._active_state_id = None
    relay.revive(server._relay_complete)          # boot path; re-registers, must not wipe payload
    check("revived flow completes", wait_flow_done())
    check("outcome success after revive", appdb.get_setting("auth_flow_outcome") == "success")

def scenario_browser_only(client, account_id):
    print("\n[6] Relay unreachable: browser redirect alone still works")
    reset_flow()
    old = relay.RELAY_BASE
    relay.RELAY_BASE = "http://127.0.0.1:9"      # relay dead for the app
    try:
        state, code = start_reauth(client, account_id)
        r = client.get(f"/callback?code={code}&state={state}")
        check("browser completes without relay", appdb.get_setting("auth_flow_outcome") == "success")
        check("routed to status", "/status" in (r.headers.get("Location") or ""))
    finally:
        relay.RELAY_BASE = old

def scenario_multi_account(client, account_id):
    print("\n[7] Multi-account: relay completion routes to picker; stale submit blocked")
    reset_flow()
    EB_STATE["accounts"] = [{"uid": "acc-1"}, {"uid": "acc-2"}]
    try:
        state, code = start_reauth(client, account_id)
        d = page_deliver(state, code)
        check("flow done (picker)", wait_flow_done() and appdb.get_setting("auth_flow_outcome") == "picker")
        check("picker state stored", bool(appdb.get_setting("pending_auth_accounts")))
        stale = client.post("/pick-account", data={"account_uid": "acc-1", "session_id": "sess-STALE"})
        check("stale picker submit rejected", "/pick-account" in (stale.headers.get("Location") or ""))
        good = client.post("/pick-account", data={"account_uid": "acc-1",
                                                  "session_id": appdb.get_setting("pending_auth_session_id")})
        check("valid picker submit accepted", "/status" in (good.headers.get("Location") or ""))
    finally:
        EB_STATE["accounts"] = [{"uid": "acc-1"}]

def scenario_double_click_after_done(client, account_id):
    print("\n[8] Late manual click after relay already finished: friendly routing, no re-exchange")
    reset_flow()
    EB_STATE["sessions_calls"] = 0
    state, code = start_reauth(client, account_id)
    page_deliver(state, code)
    wait_flow_done()
    calls_before = EB_STATE["sessions_calls"]
    r = client.get(f"/callback?code={code}&state={state}")   # user clicks the manual button later
    check("no second exchange", EB_STATE["sessions_calls"] == calls_before)
    check("late click routed to status", "/status" in (r.headers.get("Location") or ""))

def main():
    if os.system(f"curl -s --max-time 3 {RELAY}/health > /dev/null") != 0:
        print("license-api worker not running on 8799; start wrangler dev first"); sys.exit(2)
    open(NODE_ENC, "w").write(ENC_JS)
    start_mock_eb()
    make_eb_pem()
    seed_license()
    account_id = seed_bank_account()
    client = server.app.test_client()

    scenario_relay_only(client, account_id)
    scenario_race(client, account_id)
    scenario_cancel(client, account_id)
    scenario_stray_cancel_ignored(client, account_id)
    scenario_restart_revive(client, account_id)
    scenario_browser_only(client, account_id)
    scenario_multi_account(client, account_id)
    scenario_double_click_after_done(client, account_id)

    print(f"\n===== {len(PASS)} passed, {len(FAIL)} failed =====")
    if FAIL:
        print("FAILED:", *FAIL, sep="\n  - ")
        sys.exit(1)

if __name__ == "__main__":
    main()
