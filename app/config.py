import os
import json

CONFIG_FILE = "/data/config.json"

# Defaults — all overridable by config.json or environment variables
LICENCE_KEY          = ""
ACTUAL_URL           = ""
ACTUAL_PASSWORD      = ""
ACTUAL_SYNC_ID       = ""
ACTUAL_ACCOUNT       = "Revolut"
EB_APPLICATION_ID    = ""
EB_BANK_NAME         = "Revolut"
EB_BANK_COUNTRY      = "PT"
EB_PSU_TYPE          = "personal"
SYNC_TIME            = "06:00"
SYNC_FREQUENCY       = "24"
START_SYNC_DATE      = ""
ACCOUNT_HOLDER_NAME  = ""
NOTIFY_EMAIL         = ""
SMTP_USER            = ""
SMTP_PASSWORD        = ""
SMTP_HOST            = ""
SMTP_PORT            = "587"
BRIDGE_BANK_URL      = ""

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
