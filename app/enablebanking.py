import time, uuid, logging, requests
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import jwt
from . import config, db

logger  = logging.getLogger(__name__)
EB_API  = "https://api.enablebanking.com"
KEY_FILE = "/data/private.pem"

def _get_app_id():
    """Extract app ID from the key file using JWT decode — same UUID as the filename."""
    import glob, os
    # Try config first
    if config.EB_APPLICATION_ID:
        return config.EB_APPLICATION_ID
    # Fall back to reading from the pem files in /data
    for f in glob.glob("/data/*.pem"):
        name = os.path.splitext(os.path.basename(f))[0]
        if len(name) == 36:  # UUID length
            return name
    raise RuntimeError("Could not determine Enable Banking App ID. Make sure your .pem file is in /data/")

def _make_headers():
    key_data = open(KEY_FILE, "rb").read()
    key = load_pem_private_key(key_data, password=None)
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com", "aud": "api.enablebanking.com",
        "iat": now, "exp": now + 3600,
        "jti": str(uuid.uuid4()), "sub": _get_app_id(),
    }
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": _get_app_id()})
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def start_auth(bank_name: str, bank_country: str) -> dict:
    valid_until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 180 * 24 * 3600))
    state_val   = str(uuid.uuid4())
    body = {
        "access":       {"valid_until": valid_until},
        "aspsp":        {"name": bank_name, "country": bank_country},
        "state":        state_val,
        "redirect_url": f"{config.BRIDGE_BANK_URL}/callback" if config.BRIDGE_BANK_URL else "https://enablebanking.com/",
        "psu_type":     config.EB_PSU_TYPE,
    }
    db.set_setting("pending_session_state", state_val)
    db.set_setting("pending_session_valid_until", valid_until)
    r = requests.post(f"{EB_API}/auth", json=body, headers=_make_headers())
    r.raise_for_status()
    return {"url": r.json()["url"]}

def complete_auth(code: str, state: str) -> bool:
    r = requests.post(f"{EB_API}/sessions", json={"code": code, "state": state}, headers=_make_headers())
    r.raise_for_status()
    data       = r.json()
    session_id = data["session_id"]
    accounts   = data.get("accounts", [])
    if not accounts:
        return False
    chosen      = accounts[0]
    account_uid = chosen.get("uid") or chosen.get("account_uid") or chosen.get("resource_id")
    valid_until = db.get_setting("pending_session_valid_until")
    db.set_setting("eb_session_id",     session_id)
    db.set_setting("eb_account_uid",    account_uid)
    db.set_setting("eb_session_expiry", valid_until)
    return True

def check_token_expiry():
    exp = db.get_setting("eb_session_expiry")
    if not exp:
        return None
    try:
        expiry = datetime.fromisoformat(exp)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except Exception:
        return None

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
