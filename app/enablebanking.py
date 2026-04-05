import time, uuid, logging, requests
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import jwt
from . import config, db

logger  = logging.getLogger(__name__)
EB_API  = "https://api.enablebanking.com"
KEY_FILE = "/data/private.pem"

def _get_app_id():
    """Extract app ID from config, DB, or .pem filename."""
    import glob, os
    if config.EB_APPLICATION_ID:
        return config.EB_APPLICATION_ID
    app_id = db.get_setting("eb_app_id")
    if app_id:
        return app_id
    for f in glob.glob("/data/*.pem"):
        name = os.path.splitext(os.path.basename(f))[0]
        if len(name) == 36:
            return name
    raise RuntimeError(
        "Enable Banking Application ID not found. Go to the Bank setup page in Bridge Bank and upload your .pem file from Enable Banking. "
        "The filename should look like 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.pem'."
    )

def _make_headers():
    import glob, os
    pem_content = db.get_setting("eb_pem_content")
    if pem_content:
        key_data = pem_content.encode()
    else:
        key_path = KEY_FILE
        if not os.path.exists(key_path):
            pem_files = glob.glob("/data/*.pem")
            if not pem_files:
                raise RuntimeError(
                    "No .pem file found. Go to the Bank setup page in Bridge Bank and upload your .pem file from Enable Banking."
                )
            key_path = pem_files[0]
        key_data = open(key_path, "rb").read()
    key = load_pem_private_key(key_data, password=None)
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com", "aud": "api.enablebanking.com",
        "iat": now, "exp": now + 3600,
        "jti": str(uuid.uuid4()), "sub": _get_app_id(),
    }
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": _get_app_id()})
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def start_auth(bank_name: str, bank_country: str, psu_type: str = "") -> dict:
    valid_until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 180 * 24 * 3600))
    state_val   = str(uuid.uuid4())
    body = {
        "access":       {"valid_until": valid_until},
        "aspsp":        {"name": bank_name, "country": bank_country},
        "state":        f"bridge-bank-auth|{config.BRIDGE_BANK_URL or "http://localhost:3002"}|{state_val}",
        "redirect_url": "https://bridgebank.app/callback",
        "psu_type":     psu_type or config.EB_PSU_TYPE,
    }
    db.set_setting("pending_session_state", state_val)
    db.set_setting("pending_session_valid_until", valid_until)
    logger.info("Starting auth for %s (%s) with psu_type=%s", bank_name, bank_country, body["psu_type"])
    r = requests.post(f"{EB_API}/auth", json=body, headers=_make_headers())
    r.raise_for_status()
    return {"url": r.json()["url"]}

def complete_auth(code: str, state: str) -> dict:
    """Complete OAuth flow. Returns dict with session_id, account_uid, valid_until or None on failure."""
    # Strip embedded BRIDGE_BANK_URL from state before sending to Enable Banking
    clean_state = state.split("|")[-1] if "|" in state else state
    r = requests.post(f"{EB_API}/sessions", json={"code": code, "state": clean_state}, headers=_make_headers())
    r.raise_for_status()
    data       = r.json()
    session_id = data["session_id"]
    accounts   = data.get("accounts", [])
    logger.info("Bank returned %d account(s) via Enable Banking", len(accounts))
    if not accounts:
        return None
    valid_until = db.get_setting("pending_session_valid_until")
    return {
        "session_id": session_id,
        "accounts": accounts,
        "valid_until": valid_until,
    }

def check_token_expiry():
    """Return the minimum days left across all bank accounts, or None if no accounts."""
    accounts = db.get_all_bank_accounts()
    if not accounts:
        return None
    min_days = None
    for acct in accounts:
        if acct.get("sync_mode") == "balance":
            continue
        exp = acct.get("session_expiry")
        if not exp:
            continue
        try:
            expiry = datetime.fromisoformat(exp)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            if min_days is None or days < min_days:
                min_days = days
        except Exception:
            continue
    return min_days

def get_banks() -> list:
    r = requests.get(f"{EB_API}/aspsps", headers=_make_headers())
    r.raise_for_status()
    return [
        {"name": b["name"], "country": b["country"]}
        for b in r.json().get("aspsps", [])
    ]

def get_banks_public() -> list:
    r = requests.get("https://api.enablebanking.com/aspsps")
    r.raise_for_status()
    return [
        {"name": b["name"], "country": b["country"]}
        for b in r.json().get("aspsps", [])
    ]
