import json
import requests
import hashlib
import subprocess
import platform
import logging
import uuid
from . import db

logger = logging.getLogger(__name__)

LICENCE_BASE = "https://api.bridgebank.app"


def _cache_license_info(info):
    db.set_setting("licence_info_cache", json.dumps(info))


def _get_cached_license_info():
    raw = db.get_setting("licence_info_cache")
    if raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    return None

def _get_hw_uuid():
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                timeout=5, stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        elif system == "Windows":
            out = subprocess.check_output(
                ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"],
                timeout=5, stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.splitlines():
                if "MachineGuid" in line:
                    return line.strip().split()[-1]
        elif system == "Linux":
            try:
                return open("/etc/machine-id").read().strip()
            except FileNotFoundError:
                pass
    except Exception:
        pass
    return ""

def _get_fingerprint():
    stored = db.get_setting("license_instance_id_v2")
    if stored:
        return stored
    # Migrating from v1: deactivate old fingerprint to free the activation slot
    old_fp = db.get_setting("license_instance_id")
    if old_fp:
        key = db.get_setting("licence_key")
        if key:
            try:
                requests.post(
                    LICENCE_BASE + "/deactivate",
                    json={"license_key": key, "machine_fingerprint": old_fp},
                    timeout=10,
                )
            except requests.RequestException:
                pass
        db.set_setting("license_instance_id", "")
    parts = [
        str(uuid.getnode()),
        _get_hw_uuid(),
    ]
    raw = "|".join(parts)
    fp = hashlib.sha256(raw.encode()).hexdigest()[:32]
    db.set_setting("license_instance_id_v2", fp)
    return fp

def get_machine_fingerprint():
    return _get_fingerprint()

def _post_json(path, payload, timeout=10):
    resp = requests.post(LICENCE_BASE + path, json=payload, timeout=timeout)
    try:
        data = resp.json()
    except ValueError:
        data = {}
    return resp, data

def activate(key):
    fp = _get_fingerprint()
    try:
        resp, data = _post_json(
            "/activate",
            {"license_key": key, "machine_fingerprint": fp, "instance_name": "bridge-bank"},
        )
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
        # Allow offline only if this key was previously activated successfully
        if db.get_setting("licence_key") == key:
            return {"valid": True, "error": None, "offline": True}
        return {"valid": False, "error": "Could not reach the license server. Check your internet connection and try again."}

def deactivate():
    from . import config
    key = config.LICENCE_KEY
    fp = _get_fingerprint()
    if not key:
        return {"success": False, "error": "No active license to deactivate."}
    try:
        resp, data = _post_json(
            "/deactivate",
            {"license_key": key, "machine_fingerprint": fp},
        )
        if resp.status_code == 200:
            db.set_setting("licence_key", "")
            db.set_setting("license_instance_id", "")
            db.set_setting("licence_validated", "")
            db.set_setting("licence_info_cache", "")
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
        resp, data = _post_json(
            "/validate",
            {"license_key": key, "machine_fingerprint": fp},
        )
        if resp.status_code == 200 and data.get("valid"):
            db.set_setting("licence_validated", "1")
            return {"valid": True, "error": None}
        else:
            # Fingerprint may have changed after update — try re-activating
            reactivation = activate(key)
            if reactivation.get("valid"):
                db.set_setting("licence_validated", "1")
                return {"valid": True, "error": None}
            msg = data.get("error") or "Invalid license key."
            return {"valid": False, "error": msg}
    except requests.RequestException as e:
        logger.warning("License check failed (network): %s", e)
        # Allow offline if this key was previously activated and validated
        if db.get_setting("licence_key") and db.get_setting("licence_validated"):
            return {"valid": True, "error": None, "offline": True}
        return {"valid": False, "error": "Could not reach the license server. Check your internet connection."}

def get_activation_info():
    from . import config
    key = config.LICENCE_KEY
    defaults = {"usage": 0, "limit": 2, "bank_account_limit": 2, "is_trial": False, "expires_at": None}
    if not key:
        return {**defaults, "bank_seat_usage": 0}
    try:
        resp, d = _post_json("/info", {"license_key": key}, timeout=5)
        if resp.status_code == 200:
            info = {
                "usage": d.get("activation_usage", 0),
                "limit": d.get("activation_limit", 2),
                "bank_account_limit": d.get("bank_account_limit", 2),
                "bank_seat_usage": d.get("bank_seat_usage", 0),
                "is_trial": d.get("is_trial", False),
                "expires_at": d.get("expires_at"),
            }
            _cache_license_info(info)
            return info
    except Exception:
        pass
    cached = _get_cached_license_info()
    if cached:
        return cached
    return {**defaults, "bank_seat_usage": 0}

def claim_bank_seat(account, key=None):
    from . import config
    key = key or config.LICENCE_KEY
    if not key:
        return {"ok": False, "error": "No license key configured."}
    seat_id = (account.get("license_seat_id") or "").strip()
    if not seat_id:
        return {"ok": False, "error": "Missing local bank seat ID."}
    fp = _get_fingerprint()
    payload = {
        "license_key": key,
        "machine_fingerprint": fp,
        "seat_id": seat_id,
        "bank_name": account.get("bank_name", ""),
        "actual_account": account.get("actual_account", ""),
        "sync_mode": account.get("sync_mode", "transactions"),
    }
    try:
        resp, data = _post_json("/bank-seats/claim", payload)
        if resp.status_code == 200:
            return {
                "ok": True,
                "used": data.get("used"),
                "limit": data.get("limit"),
            }
        return {
            "ok": False,
            "error": data.get("error") or "Could not reserve a bank slot for this licence.",
            "used": data.get("used"),
            "limit": data.get("limit"),
        }
    except requests.RequestException as e:
        logger.warning("Bank seat claim failed (network): %s", e)
        return {
            "ok": False,
            "error": "Could not reach the license server to confirm bank slot availability.",
            "network": True,
        }

def sync_bank_seats(accounts, key=None):
    from . import config
    key = key or config.LICENCE_KEY
    if not key:
        return {"ok": False, "error": "No license key configured."}
    fp = _get_fingerprint()
    payload = {
        "license_key": key,
        "machine_fingerprint": fp,
        "seats": [
            {
                "seat_id": account.get("license_seat_id", ""),
                "bank_name": account.get("bank_name", ""),
                "actual_account": account.get("actual_account", ""),
                "sync_mode": account.get("sync_mode", "transactions"),
            }
            for account in accounts
            if account.get("license_seat_id")
        ],
    }
    try:
        resp, data = _post_json("/bank-seats/sync", payload)
        if resp.status_code == 200:
            return {
                "ok": True,
                "used": data.get("used"),
                "limit": data.get("limit"),
            }
        return {
            "ok": False,
            "error": data.get("error") or "Could not verify bank slots for this licence.",
            "used": data.get("used"),
            "limit": data.get("limit"),
        }
    except requests.RequestException as e:
        logger.warning("Bank seat sync failed (network): %s", e)
        return {
            "ok": False,
            "error": "Could not reach the license server to verify connected bank slots.",
            "network": True,
        }
