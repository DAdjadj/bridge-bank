import os
import json
import re

CONFIG_FILE = "/data/config.json"

# Defaults — all overridable by config.json or environment variables
LICENCE_KEY          = ""
ACTUAL_URL           = ""
ACTUAL_PASSWORD      = ""
ACTUAL_ENCRYPTION_PASSWORD = ""
ACTUAL_SYNC_ID       = ""
ACTUAL_ACCOUNT       = ""
EB_APPLICATION_ID    = ""
EB_BANK_NAME         = ""
EB_BANK_COUNTRY      = ""
EB_PSU_TYPE          = "personal"
SYNC_TIME            = "06:00"
SYNC_FREQUENCY       = "24"
AUTO_LINK_TRANSFERS  = "true"
IBAN_IN_NOTES        = "false"
START_SYNC_DATE      = ""
ACCOUNT_HOLDER_NAME  = ""
NOTIFY_EMAIL         = ""
SMTP_USER            = ""
SMTP_PASSWORD        = ""
SMTP_HOST            = ""
SMTP_PORT            = "587"
SMTP_SECURITY        = "starttls"  # starttls, ssl, or none
SMTP_TLS_VERIFY      = "true"
SMTP_AUTH            = "true"
SMTP_FROM            = ""
NOTIFY_ON            = "all"
BRIDGE_BANK_URL      = ""
TIMEZONE             = ""
RELAY_ENABLED        = "true"

def _load():
    """Load config from file, then override with environment variables."""
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
        except Exception:
            pass

    g = globals()
    for key in list(g.keys()):
        if key.startswith("_") or not key.isupper():
            continue
        # config.json (wizard) takes precedence over env vars
        if key in data and data[key]:
            g[key] = data[key]
        else:
            env_val = os.environ.get(key)
            if env_val is not None:
                g[key] = env_val

def set(key: str, value: str):
    """Persist a config value to config.json and update the in-memory global."""
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
        except Exception:
            pass
    data[key] = value
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)
    globals()[key] = value

# Hours between syncs that fit evenly into a day; 0 means manual only.
_SYNC_FREQUENCIES = (0, 1, 2, 3, 4, 6, 8, 12, 24)
_DEFAULT_SYNC_TIME = "06:00"
_DEFAULT_SYNC_FREQUENCY = 24

def parse_sync_time(value):
    """'6:30' or '06:30' as '06:30'; None when it isn't a real time of day."""
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(value or "").strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        return None
    return f"{int(m.group(1)):02d}:{m.group(2)}"

def parse_sync_frequency(value):
    """Hours between syncs as an int (0 = manual only); None when not one of the choices."""
    try:
        hours = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return hours if hours in _SYNC_FREQUENCIES else None

def sync_time() -> str:
    """The saved sync time, or 06:00 if what's saved can't be read."""
    return parse_sync_time(SYNC_TIME) or _DEFAULT_SYNC_TIME

def sync_frequency() -> int:
    """The saved hours between syncs, or every 24 hours if what's saved can't be read."""
    hours = parse_sync_frequency(SYNC_FREQUENCY)
    return _DEFAULT_SYNC_FREQUENCY if hours is None else hours

def is_configured() -> bool:
    """Returns True if all required fields are set."""
    return bool(LICENCE_KEY and ACTUAL_URL and ACTUAL_PASSWORD and
                ACTUAL_SYNC_ID and ACTUAL_ACCOUNT)

def is_connected() -> bool:
    """Returns True if at least one bank account is connected."""
    from . import db
    return db.get_bank_account_count() > 0

# Load on import
_load()
