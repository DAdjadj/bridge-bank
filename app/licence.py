import requests
import hashlib
import socket
import logging
from . import db

logger = logging.getLogger(__name__)

LICENCE_BASE = "https://api.bridgebank.app"

def _get_fingerprint():
    stored = db.get_setting("license_instance_id")
    if stored:
        return stored
    raw = socket.gethostname()
    fp = hashlib.sha256(raw.encode()).hexdigest()[:32]
    db.set_setting("license_instance_id", fp)
    return fp

def activate(key):
    fp = _get_fingerprint()
    try:
        resp = requests.post(
            LICENCE_BASE + "/activate",
            json={"license_key": key, "machine_fingerprint": fp, "instance_name": "bridge-bank"},
            timeout=10,
        )
        data = resp.json()
        if resp.status_code in (200, 201) and data.get("valid"):
            db.set_setting("licence_key", key)
            return {"valid": True, "error": None}
        elif resp.status_code == 409:
            db.set_setting("licence_key", key)
            return {"valid": True, "error": None}
        else:
            msg = data.get("error") or "Invalid license key."
            return {"valid": False, "error": msg}
    except requests.RequestException as e:
        logger.warning("License activate failed (network): %s", e)
        return {"valid": True, "error": None, "offline": True}

def deactivate():
    from . import config
    key = config.LICENCE_KEY
    fp = _get_fingerprint()
    if not key:
        return {"success": False, "error": "No active license to deactivate."}
    try:
        resp = requests.post(
            LICENCE_BASE + "/deactivate",
            json={"license_key": key, "machine_fingerprint": fp},
            timeout=10,
        )
        data = resp.json()
        if resp.status_code == 200:
            db.set_setting("licence_key", "")
            db.set_setting("license_instance_id", "")
            return {"success": True, "error": None}
        else:
            msg = data.get("error") or "Deactivation failed."
            return {"success": False, "error": msg}
    except requests.RequestException as e:
        logger.warning("License deactivate failed (network): %s", e)
        return {"success": False, "error": str(e)}

def validate(key=None):
    from . import config
    key = key or config.LICENCE_KEY
    if not key:
        return {"valid": False, "error": "No license key configured."}
    fp = _get_fingerprint()
    try:
        resp = requests.post(
            LICENCE_BASE + "/validate",
            json={"license_key": key, "machine_fingerprint": fp},
            timeout=10,
        )
        data = resp.json()
        if resp.status_code == 200 and data.get("valid"):
            return {"valid": True, "error": None}
        else:
            msg = data.get("error") or "Invalid license key."
            return {"valid": False, "error": msg}
    except requests.RequestException as e:
        logger.warning("License check failed (network): %s", e)
        return {"valid": True, "error": None, "offline": True}

def get_activation_info():
    return {"usage": 0, "limit": 2}
