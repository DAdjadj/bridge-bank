import logging
import re
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify
from .. import config, db, licence, sync

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
def _get_secret_key():
    stored = db.get_setting("flask_secret_key")
    if stored:
        return stored
    import secrets as _secrets
    key = _secrets.token_hex(32)
    db.set_setting("flask_secret_key", key)
    return key

app.secret_key = _get_secret_key()

def _detect_container_name():
    """Detect container name from mounted compose file or fall back to default."""
    import os
    compose_path = "/compose/docker-compose.yml"
    if os.path.exists(compose_path):
        try:
            with open(compose_path) as f:
                for line in f:
                    if "container_name:" in line:
                        return line.split("container_name:")[-1].strip().strip('"').strip("'")
        except Exception:
            pass
    return "bridge-bank"

CONTAINER_NAME = _detect_container_name()
IMAGE_NAME = "daalves/bridge-bank:latest"

COUNTRIES = [
    ("AT","Austria"),("BE","Belgium"),("HR","Croatia"),("CY","Cyprus"),
    ("CZ","Czech Republic"),("DK","Denmark"),("EE","Estonia"),("FI","Finland"),
    ("FR","France"),("DE","Germany"),("GR","Greece"),("HU","Hungary"),
    ("IE","Ireland"),("IT","Italy"),("LV","Latvia"),("LT","Lithuania"),
    ("LU","Luxembourg"),("MT","Malta"),("NL","Netherlands"),("NO","Norway"),
    ("PL","Poland"),("PT","Portugal"),("RO","Romania"),("SK","Slovakia"),
    ("SI","Slovenia"),("ES","Spain"),("SE","Sweden"),("GB","United Kingdom"),
]

# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if not config.is_configured():
        return redirect(url_for("setup_license"))
    if not config.is_connected():
        return redirect(url_for("connect"))
    return redirect(url_for("status"))

# ---------------------------------------------------------------------------
# Setup step 1: License
# ---------------------------------------------------------------------------

@app.route("/setup", methods=["GET", "POST"])
def setup_license():
    error = None
    if request.method == "POST":
        key = request.form.get("license_key", "").strip()
        result = licence.activate(key)
        if not result["valid"] and not result.get("offline"):
            error = result["error"] or "Invalid license key."
        else:
            config.set("LICENCE_KEY", key)
            return redirect(url_for("setup_actual"))
    return render_template("setup_license.html",
        error=error,
        license_key=config.LICENCE_KEY,
        active="license",
    )

# ---------------------------------------------------------------------------
# Setup step 2: Enable Banking
# ---------------------------------------------------------------------------

@app.route("/setup/bank", methods=["GET", "POST"])
def setup_bank():
    error = None
    if request.method == "POST":
        app_id      = request.form.get("eb_app_id", "").strip()
        psu_type    = request.form.get("eb_psu_type", "personal").strip()
        pem_file    = request.files.get("pem_file")
        pem_content = ""
        if pem_file and pem_file.filename:
            pem_content = pem_file.read().decode("utf-8", errors="ignore").strip()
            if pem_content and "PRIVATE KEY" not in pem_content:
                error = "This doesn't look like a valid .pem file. Make sure you upload the private key file from Enable Banking."
        existing_pem = db.get_setting("eb_pem_content")
        if not error and not app_id:
            error = "Application ID is required."
        elif not error and not pem_content and not existing_pem:
            error = "Please upload your private.pem file."
        else:
            config.set("EB_APPLICATION_ID", app_id)
            config.set("EB_PSU_TYPE", psu_type)
            db.set_setting("eb_app_id", app_id)
            if pem_content:
                db.set_setting("eb_pem_content", pem_content)
            return redirect(url_for("setup_actual"))
    return render_template("setup_bank.html",
        error=error,
        eb_app_id=config.EB_APPLICATION_ID or db.get_setting("eb_app_id"),
        eb_psu_type=config.EB_PSU_TYPE,
        pem_uploaded=bool(db.get_setting("eb_pem_content")),
        active="bank",
    )

# ---------------------------------------------------------------------------
# Setup step 3: Actual Budget
# ---------------------------------------------------------------------------

@app.route("/setup/actual", methods=["GET", "POST"])
def setup_actual():
    error = None
    if request.method == "POST":
        url      = request.form.get("actual_url", "").strip().rstrip("/")
        password = request.form.get("actual_password", "").strip()
        sync_id  = request.form.get("actual_sync_id", "").strip()
        account  = request.form.get("actual_account", "").strip()
        if not url or not password or not sync_id or not account:
            error = "All fields are required."
        else:
            # Validate connection before saving
            try:
                from actual import Actual
                with Actual(base_url=url, password=password, file=sync_id, data_dir="/data/actual-cache"):
                    pass
            except ConnectionError:
                error = f"Could not reach Actual Budget at {url}. Make sure the URL is correct and Actual Budget is running."
            except Exception as e:
                err_str = str(e).lower()
                if "password" in err_str or "auth" in err_str or "401" in err_str:
                    error = "Wrong password. Check your Actual Budget password and try again."
                elif "file" in err_str or "sync" in err_str or "not found" in err_str:
                    error = "Sync ID not found. Open Actual Budget → Settings → Show advanced settings → Sync ID."
                else:
                    error = f"Could not connect to Actual Budget: {e}"
            if not error:
                config.set("ACTUAL_URL", url)
                config.set("ACTUAL_PASSWORD", password)
                config.set("ACTUAL_SYNC_ID", sync_id)
                config.set("ACTUAL_ACCOUNT", account)
                return redirect(url_for("setup_notifications"))
    return render_template("setup_actual.html",
        error=error,
        actual_url=config.ACTUAL_URL,
        actual_password=config.ACTUAL_PASSWORD,
        actual_sync_id=config.ACTUAL_SYNC_ID,
        actual_account=config.ACTUAL_ACCOUNT,
        active="actual",
    )

# ---------------------------------------------------------------------------
# Setup step 4: Notifications
# ---------------------------------------------------------------------------

@app.route("/setup/notifications", methods=["GET", "POST"])
def setup_notifications():
    error = None
    if request.method == "POST":
        notify_email  = request.form.get("notify_email", "").strip()
        smtp_user     = request.form.get("smtp_user", "").strip()
        smtp_password = request.form.get("smtp_password", "").strip()
        smtp_from     = request.form.get("smtp_from", "").strip()
        smtp_host     = request.form.get("smtp_host", "").strip()
        notify_on     = request.form.get("notify_on", "all").strip()
        holder_name   = request.form.get("holder_name", "").strip()
        if not notify_email or not smtp_user or not smtp_password:
            error = "Notification email and sending credentials are required."
        else:
            config.set("NOTIFY_EMAIL", notify_email)
            config.set("SMTP_USER", smtp_user)
            config.set("SMTP_PASSWORD", smtp_password)
            config.set("SMTP_FROM", smtp_from)
            config.set("SMTP_HOST", smtp_host)
            config.set("NOTIFY_ON", notify_on)
            config.set("ACCOUNT_HOLDER_NAME", holder_name)
            scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
            host   = request.headers.get("X-Forwarded-Host", request.host)
            config.set("BRIDGE_BANK_URL", f"{scheme}://{host}")
            return redirect(url_for("connect"))
    return render_template("setup_notifications.html",
        error=error,
        notify_email=config.NOTIFY_EMAIL,
        smtp_user=config.SMTP_USER,
        smtp_password=config.SMTP_PASSWORD,
        smtp_from=config.SMTP_FROM,
        smtp_host=config.SMTP_HOST,
        notify_on=config.NOTIFY_ON,
        holder_name=config.ACCOUNT_HOLDER_NAME,
        active="notifications",
    )

@app.route("/email/test", methods=["POST"])
def test_email():
    # Save current form values so the test uses what the user sees
    data = request.get_json(silent=True) or {}
    if data.get("notify_email"):
        config.set("NOTIFY_EMAIL", data["notify_email"].strip())
    if data.get("smtp_user"):
        config.set("SMTP_USER", data["smtp_user"].strip())
    if data.get("smtp_password"):
        config.set("SMTP_PASSWORD", data["smtp_password"].strip())
    try:
        from .. import email_notify
        email_notify.send("Bridge Bank: test email", "This is a test email from Bridge Bank. If you're reading this, your email notifications are working correctly.", raise_on_error=True)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/setup/sync", methods=["GET", "POST"])
def setup_sync():
    error = None
    if request.method == "POST":
        sync_time = request.form.get("sync_time", "06:00").strip()
        sync_frequency = request.form.get("sync_frequency", "24").strip()
        start_date = request.form.get("start_sync_date", "").strip()
        config.set("SYNC_TIME", sync_time)
        config.set("SYNC_FREQUENCY", sync_frequency)
        if start_date:
            config.set("START_SYNC_DATE", start_date)
        _start_scheduler_if_ready()
        return redirect(url_for("status"))
    has_synced = bool(db.get_last_sync())
    return render_template("setup_sync.html",
        error=error,
        sync_time=config.SYNC_TIME or "06:00",
        sync_frequency=getattr(config, 'SYNC_FREQUENCY', '24') or "24",
        start_sync_date=config.START_SYNC_DATE or __import__('datetime').date.today().isoformat(),
        is_configured=config.is_configured(),
        has_synced=has_synced,
        active="sync",
    )

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/bank-status")
def bank_status():
    return jsonify({"connected": db.get_bank_account_count() > 0})

@app.route("/api/detect-url")
def detect_url():
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    host   = request.headers.get("X-Forwarded-Host", request.host)
    return jsonify({"url": f"{scheme}://{host}"})

@app.route("/api/last-sync")
def last_sync_api():
    return jsonify({"ran_at": db.get_last_sync() or ""})

@app.route("/api/actual-accounts")
def actual_accounts_api():
    """List account names from Actual Budget for validation/autocomplete."""
    try:
        from actual import Actual
        from actual.queries import get_accounts
        with Actual(base_url=config.ACTUAL_URL, password=config.ACTUAL_PASSWORD,
                    file=config.ACTUAL_SYNC_ID, data_dir="/data/actual-cache") as actual:
            accounts = get_accounts(actual.session)
            return jsonify([a.name for a in accounts])
    except Exception as e:
        logger.error("Failed to list Actual accounts: %s", e)
        return jsonify([])

# ---------------------------------------------------------------------------
# Connect (bank OAuth)
# ---------------------------------------------------------------------------

@app.route("/connect", methods=["GET", "POST"])
def connect():
    error    = None
    auth_url = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "upload_pem":
            pem_file = request.files.get("pem_file")
            app_id   = request.form.get("eb_app_id", "").strip()
            if not pem_file or not pem_file.filename:
                error = "Please select a .pem file."
            elif not app_id:
                error = "Application ID is required."
            else:
                pem_content = pem_file.read().decode("utf-8", errors="ignore").strip()
                if "PRIVATE KEY" not in pem_content:
                    error = "This doesn't look like a valid .pem file. Make sure you upload the private key file from Enable Banking."
                else:
                    db.set_setting("eb_pem_content", pem_content)
                    db.set_setting("eb_app_id", app_id)
                    config.set("EB_APPLICATION_ID", app_id)
                    return redirect(url_for("connect"))

        elif action == "start":
            bank_name       = request.form.get("bank_name", "").strip()
            bank_country    = request.form.get("bank_country", "").strip()
            actual_account  = request.form.get("actual_account", "").strip()
            start_sync_date = request.form.get("start_sync_date", "").strip()
            psu_type        = request.form.get("psu_type", "personal").strip()
            if not bank_name or not bank_country:
                error = "Please select a bank."
            elif not actual_account:
                error = "Please enter the Actual Budget account name."
            else:
                # Validate that the account exists in Actual Budget
                try:
                    from actual import Actual
                    from actual.queries import get_accounts
                    with Actual(base_url=config.ACTUAL_URL, password=config.ACTUAL_PASSWORD,
                                file=config.ACTUAL_SYNC_ID, data_dir="/data/actual-cache") as actual:
                        actual_names = [a.name for a in get_accounts(actual.session)]
                    if actual_account not in actual_names:
                        close_matches = [n for n in actual_names if actual_account.lower() in n.lower() or n.lower() in actual_account.lower()]
                        hint = f" Did you mean: {', '.join(close_matches)}?" if close_matches else f" Available accounts: {', '.join(actual_names)}." if actual_names else ""
                        error = f"Account \"{actual_account}\" not found in Actual Budget.{hint}"
                except Exception as e:
                    logger.warning("Could not validate Actual account: %s", e)
                if not error:
                    config.set("EB_BANK_NAME", bank_name)
                    config.set("EB_BANK_COUNTRY", bank_country)
                    db.set_setting("pending_actual_account", actual_account)
                    db.set_setting("pending_bank_name", bank_name)
                    db.set_setting("pending_bank_country", bank_country)
                    db.set_setting("pending_start_sync_date", start_sync_date)
                    try:
                        # Update BRIDGE_BANK_URL from current request so the OAuth
                        # callback redirects back through the same scheme (HTTPS via Caddy)
                        scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
                        host   = request.headers.get("X-Forwarded-Host", request.host)
                        config.set("BRIDGE_BANK_URL", f"{scheme}://{host}")
                        from .. import enablebanking
                        result   = enablebanking.start_auth(bank_name, bank_country, psu_type=psu_type)
                        auth_url = result["url"]
                    except Exception as e:
                        error = f"Could not start bank connection: {e}"

        elif action == "cancel":
            db.set_setting("pending_session_id", "")
            db.set_setting("pending_actual_account", "")
            db.set_setting("pending_bank_name", "")
            db.set_setting("pending_bank_country", "")
            return redirect(url_for("connect"))

    all_accounts = db.get_all_bank_accounts()
    days_left    = _get_days_left()
    success      = request.args.get("success")
    pem_ready    = bool(db.get_setting("eb_pem_content") or __import__('os').path.exists("/data/private.pem"))

    # Fetch bank account limit from licence API
    bank_account_limit = 2
    try:
        import requests as _requests
        key = config.LICENCE_KEY
        if key:
            resp = _requests.post("https://api.bridgebank.app/info", json={"license_key": key}, timeout=5)
            if resp.status_code == 200:
                bank_account_limit = resp.json().get("bank_account_limit", 2)
    except Exception:
        pass

    return render_template("connect.html",
        error=error,
        success=success,
        auth_url=auth_url,
        all_accounts=all_accounts,
        days_left=days_left,
        pem_ready=pem_ready,
        eb_app_id=config.EB_APPLICATION_ID or db.get_setting("eb_app_id"),
        bank_account_limit=bank_account_limit,
        bank_slot_url=f"https://buy.stripe.com/4gM9AMg348nt2Y7185cMM04?client_reference_id={config.LICENCE_KEY}",
        today=__import__('datetime').date.today().isoformat(),
        active="connect",
    )

# ---------------------------------------------------------------------------
# Re-authorise existing bank
# ---------------------------------------------------------------------------

@app.route("/connect/reauthorise", methods=["POST"])
def reauthorise():
    bank_name    = request.form.get("bank_name", "").strip()
    bank_country = request.form.get("bank_country", "").strip()
    if not bank_name or not bank_country:
        return redirect(url_for("connect"))
    try:
        from .. import enablebanking
        db.set_setting("pending_bank_name", bank_name)
        db.set_setting("pending_bank_country", bank_country)
        result   = enablebanking.start_auth(bank_name, bank_country)
        auth_url = result["url"]
    except Exception as e:
        logger.error("Failed to start reauth: %s", e)
        return redirect(url_for("connect") + f"?error=Could not start re-authorisation: {e}")

    all_accounts = db.get_all_bank_accounts()
    bank_account_limit = 2
    try:
        import requests as _requests
        key = config.LICENCE_KEY
        if key:
            resp = _requests.post("https://api.bridgebank.app/info", json={"license_key": key}, timeout=5)
            if resp.status_code == 200:
                bank_account_limit = resp.json().get("bank_account_limit", 2)
    except Exception:
        pass

    return render_template("connect.html",
        error=None,
        success=None,
        auth_url=auth_url,
        all_accounts=all_accounts,
        pem_ready=True,
        eb_app_id=config.EB_APPLICATION_ID or db.get_setting("eb_app_id"),
        bank_account_limit=bank_account_limit,
        bank_slot_url=f"https://buy.stripe.com/4gM9AMg348nt2Y7185cMM04?client_reference_id={config.LICENCE_KEY}",
        today=__import__('datetime').date.today().isoformat(),
        active="connect",
    )

# ---------------------------------------------------------------------------
# OAuth callback
# ---------------------------------------------------------------------------

def _save_bank_account(session_id, account_uid, valid_until):
    actual_account  = db.get_setting("pending_actual_account") or config.ACTUAL_ACCOUNT
    bank_name       = db.get_setting("pending_bank_name") or config.EB_BANK_NAME
    bank_country    = db.get_setting("pending_bank_country") or config.EB_BANK_COUNTRY
    start_sync_date = db.get_setting("pending_start_sync_date") or ""
    db.add_bank_account(
        session_id=session_id,
        account_uid=account_uid,
        bank_name=bank_name,
        bank_country=bank_country,
        actual_account=actual_account,
        session_expiry=valid_until,
        start_sync_date=start_sync_date,
    )
    # Clear pending settings
    for key in ["pending_actual_account", "pending_bank_name", "pending_bank_country",
                "pending_start_sync_date", "pending_session_state", "pending_session_valid_until"]:
        db.set_setting(key, "")
    _start_scheduler_if_ready()
    threading.Thread(target=sync.run, daemon=True).start()

@app.route("/callback")
def callback():
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error")
    if error or not code:
        logger.warning("Callback received error=%s code=%s", error, bool(code))
        return redirect(url_for("connect") + "?error=Bank connection was cancelled or denied. Please try again.")
    try:
        from .. import enablebanking
        result = enablebanking.complete_auth(code=code, state=state)
        if result:
            accounts = result["accounts"]
            logger.info("Callback: %d account(s) returned, session=%s", len(accounts), result["session_id"])
            if len(accounts) == 1:
                account_uid = accounts[0].get("uid") or accounts[0].get("account_uid") or accounts[0].get("resource_id")
                logger.info("Auto-connecting single account uid=%s", account_uid)
                _save_bank_account(result["session_id"], account_uid, result.get("valid_until", ""))
                return redirect(url_for("status"))
            else:
                import json
                logger.info("Multiple accounts — redirecting to account picker")
                db.set_setting("pending_auth_session_id", result["session_id"])
                db.set_setting("pending_auth_accounts", json.dumps(accounts))
                db.set_setting("pending_auth_valid_until", result.get("valid_until", ""))
                return redirect(url_for("pick_account"))
        else:
            logger.warning("Callback: complete_auth returned no accounts")
            return redirect(url_for("connect") + "?error=Your bank did not return any accounts. This may happen if you declined account access during authorisation, or if the selected account type is not supported by your bank through open banking. Please try again and make sure to approve access to at least one account.")
    except Exception as e:
        logger.error("Callback failed: %s", e)
        return redirect(url_for("connect") + "?error=Bank connection failed: " + str(e) + ". If this keeps happening, please download your logs from the Status page and send them to support@bridgebank.app.")

@app.route("/pick-account")
def pick_account():
    import json
    accounts_json = db.get_setting("pending_auth_accounts")
    if not accounts_json:
        return redirect(url_for("connect"))
    accounts = json.loads(accounts_json)
    return render_template("pick_account.html", accounts=accounts, active="connect")

@app.route("/pick-account", methods=["POST"])
def pick_account_post():
    account_uid = request.form.get("account_uid")
    if not account_uid:
        return redirect(url_for("pick_account"))
    session_id  = db.get_setting("pending_auth_session_id")
    valid_until = db.get_setting("pending_auth_valid_until")
    _save_bank_account(session_id, account_uid, valid_until)
    for key in ["pending_auth_session_id", "pending_auth_accounts", "pending_auth_valid_until"]:
        db.set_setting(key, "")
    return redirect(url_for("status"))

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@app.route("/status")
def status():
    if not config.is_configured():
        return redirect(url_for("setup_license"))
    if not config.is_connected():
        return redirect(url_for("connect"))

    page         = request.args.get("page", 1, type=int)
    log_data     = db.get_sync_log_page(page=page, per_page=5)
    syncs        = log_data["syncs"]
    all_accounts = db.get_all_bank_accounts()
    days_left    = _get_days_left()
    last_sync    = db.get_last_sync()
    act_info     = licence.get_activation_info()

    license_sync_failed = False
    val = licence.validate()
    if not val.get("valid") and not val.get("offline"):
        license_sync_failed = True

    # Fun stats
    import random
    all_syncs = db.get_recent_syncs(limit=9999)
    # Streak: group entries by sync run (within 30s of each other), count runs with at least one success
    streak = 0
    recent = db.get_recent_syncs(limit=200)
    if recent:
        from datetime import datetime
        runs = []
        current_run = [recent[0]]
        for r in recent[1:]:
            try:
                t1 = datetime.fromisoformat(current_run[-1]["ran_at"])
                t2 = datetime.fromisoformat(r["ran_at"])
                if abs((t1 - t2).total_seconds()) < 5:
                    current_run.append(r)
                else:
                    runs.append(current_run)
                    current_run = [r]
            except Exception:
                runs.append(current_run)
                current_run = [r]
        runs.append(current_run)
        for run in runs:
            if any(e["status"] == "success" for e in run):
                streak += 1
            else:
                break
    total_tx = sum(r.get("tx_count", 0) for r in all_syncs if r["status"] == "success")

    fun_messages = [
        "Your finances are in good hands.",
        "Another day, another sync.",
        "Everything's running smoothly.",
        "Your bank called. They said everything's fine.",
        "Transactions delivered. You're welcome.",
        "Syncing like clockwork.",
        "Actual Budget is looking sharp.",
        "All quiet on the banking front.",
        "Nothing to worry about here.",
        "Your data, your machine, your peace of mind.",
    ]
    fun_message = random.choice(fun_messages)

    return render_template("status.html",
        syncs=syncs,
        all_accounts=all_accounts,
        days_left=days_left,
        last_sync=last_sync,
        sync_time=config.SYNC_TIME,
        sync_frequency=getattr(config, 'SYNC_FREQUENCY', '24') or '24',
        sync_times=_get_sync_times(),
        notify_email=config.NOTIFY_EMAIL,
        activation_usage=act_info["usage"],
        activation_limit=act_info["limit"],
        is_trial=act_info.get("is_trial", False),
        trial_expires_at=act_info.get("expires_at", "")[:10] if act_info.get("expires_at") else None,
        license_sync_failed=license_sync_failed,
        license_limit_reached=(license_sync_failed and act_info["usage"] >= act_info["limit"] and act_info["limit"] > 0),
        page=log_data["page"],
        total_pages=log_data["total_pages"],
        active="status",
        update_mode=db.get_setting("update_mode"),
        update_available=db.get_setting("update_available") == "1",
        total_tx=total_tx,
        streak=streak,
        fun_message=fun_message,
    )

# ---------------------------------------------------------------------------
# License deactivate
# ---------------------------------------------------------------------------

@app.route("/sync/clear", methods=["POST"])
def clear_sync_log():
    db.clear_sync_log()
    return redirect(url_for("status"))

@app.route("/settings/deactivate", methods=["POST"])
def deactivate_license():
    result = licence.deactivate()
    if result["success"]:
        config.set("LICENCE_KEY", "")
        return redirect(url_for("setup_license"))
    return redirect(url_for("status"))

# ---------------------------------------------------------------------------
# Sync now
# ---------------------------------------------------------------------------

_sync_running = False

@app.route("/sync/now", methods=["POST"])
def sync_now():
    global _sync_running
    _sync_running = True
    def _run():
        global _sync_running
        try:
            sync.run()
        finally:
            _sync_running = False
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/sync-status")
def sync_status():
    return jsonify({"running": _sync_running})


# ---------------------------------------------------------------------------
# Disconnect
# ---------------------------------------------------------------------------

@app.route("/connect/reset-pem")
def reset_pem():
    db.set_setting("eb_pem_content", "")
    db.set_setting("eb_app_id", "")
    return redirect(url_for("connect"))

@app.route("/disconnect", methods=["POST"])
def disconnect():
    account_id = request.form.get("account_id")
    if account_id:
        db.remove_bank_account(int(account_id))
    return redirect(url_for("connect"))

@app.route("/reset-sync", methods=["POST"])
def reset_sync():
    account_id = request.form.get("account_id")
    reset_date = request.form.get("reset_date", "").strip()
    if account_id:
        from .. import sync as sync_mod
        state = sync_mod._load_state()
        acct_state = state.get("accounts", {})
        if account_id in acct_state:
            del acct_state[account_id]
            sync_mod._save_state(state)
        if reset_date:
            db.update_bank_account_field(int(account_id), "start_sync_date", reset_date)
        logger.info("Reset sync state for account %s (start_date=%s)", account_id, reset_date)
    return redirect(url_for("connect"))

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def _sanitize_logs(text):
    # Mask IBANs (2 letter country + 2 digits + up to 30 chars)
    text = re.sub(r'\b([A-Z]{2}\d{2})\w{4,}(\w{4})\b', r'\1****\2', text)
    # Mask email addresses
    text = re.sub(r'\b(\w{2})\w*(@\w+\.\w+)', r'\1***\2', text)
    # Remove large JSON account blobs from Enable Banking
    text = re.sub(r"\[?\{'account_id':.*?\}\]?", '[account data redacted]', text)
    return text

@app.route("/api/logs")
def api_logs():
    """Return recent application logs for debugging."""
    import subprocess
    lines = request.args.get("lines", "200")
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", lines, CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        )
        # docker logs sends output to stderr
        output = result.stdout + result.stderr
        output = _sanitize_logs(output)
        # Get container image ID as version identifier
        version = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()[:19].replace("sha256:", "")
        return jsonify({"logs": output, "version": version})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# Banks
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Update preference + self-update
# ---------------------------------------------------------------------------

@app.route("/update/preference", methods=["POST"])
def update_preference():
    mode = request.form.get("mode", "manual")
    db.set_setting("update_mode", mode)
    return redirect(url_for("status"))

@app.route("/update/check", methods=["GET"])
def update_check():
    import subprocess, os
    if not os.path.exists("/var/run/docker.sock"):
        return jsonify({"available": False})
    try:
        import requests as _req
        repo = IMAGE_NAME.split(":")[0]
        tag = IMAGE_NAME.split(":")[1] if ":" in IMAGE_NAME else "latest"
        token_resp = _req.get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=5)
        token = token_resp.json().get("token", "")
        accept = ", ".join([
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ])
        manifest_resp = _req.head(
            f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
            headers={"Authorization": f"Bearer {token}", "Accept": accept},
            timeout=5
        )
        remote_digest = manifest_resp.headers.get("Docker-Content-Digest", "")
        # Compare against the running container's image, not the locally pulled image.
        # This detects updates even when the image was pulled but the container wasn't recreated.
        container_image = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        local_digest = subprocess.run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", IMAGE_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        local_sha = local_digest.split("@")[-1] if "@" in local_digest else ""
        # Also check if the pulled image differs from what the container is running
        pulled_image_id = subprocess.run(
            ["docker", "inspect", "--format", "{{.Id}}", IMAGE_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        container_outdated = container_image != pulled_image_id
        available = (remote_digest != local_sha and remote_digest != "") or container_outdated
        logger.info("Update check: remote=%s local=%s container_outdated=%s available=%s", remote_digest[:20], local_sha[:20], container_outdated, available)
        return jsonify({"available": available})
    except Exception as e:
        logger.warning("Update check failed: %s", e)
        return jsonify({"available": False})

@app.route("/update/run", methods=["POST"])
def update_run():
    import subprocess, os
    if not os.path.exists("/var/run/docker.sock"):
        return jsonify({"error": "Docker socket not mounted."}), 400
    try:
        pull = subprocess.run(
            ["docker", "pull", IMAGE_NAME],
            capture_output=True, text=True, timeout=120
        )
        logger.info("Docker pull output: %s", pull.stdout.strip() or pull.stderr.strip())
        # Check if container is running the pulled image
        container_image = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        pulled_image_id = subprocess.run(
            ["docker", "inspect", "--format", "{{.Id}}", IMAGE_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        image_is_same = "Image is up to date" in pull.stdout or "Image is up to date" in pull.stderr
        container_current = container_image == pulled_image_id
        if image_is_same and container_current:
            return jsonify({"up_to_date": True})
        logger.info("Recreating container (new_image=%s, container_outdated=%s)", not image_is_same, not container_current)
        # docker compose up -d can't work from inside the container because it
        # can't stop itself. Read mount/port config from the running container
        # and recreate with docker run.
        import json as _json
        mounts_json = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        ports_json = subprocess.run(
            ["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        vol_args = []
        for m in _json.loads(mounts_json or "[]"):
            ro = ":ro" if not m.get("RW", True) else ""
            vol_args += ["-v", f"{m['Source']}:{m['Destination']}{ro}"]
        port_args = []
        for container_port, bindings in _json.loads(ports_json or "{}").items():
            for b in (bindings or []):
                host_port = b.get("HostPort", "")
                if host_port:
                    port_args += ["-p", f"{host_port}:{container_port.split('/')[0]}"]
        run_parts = ["docker", "run", "-d", "--name", CONTAINER_NAME, "--restart", "unless-stopped"] + port_args + vol_args + [IMAGE_NAME]
        run_cmd = " ".join(run_parts)
        full_cmd = f"sleep 2 && docker stop {CONTAINER_NAME} && docker rm {CONTAINER_NAME} && {run_cmd}"
        logger.info("Update command: %s", full_cmd)
        subprocess.Popen(["sh", "-c", full_cmd], start_new_session=True)
        db.set_setting("update_available", "0")
        return jsonify({"updating": True})
    except FileNotFoundError:
        return jsonify({"error": "Docker CLI not available in container."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

_banks_cache = None

@app.route("/banks")
def banks():
    global _banks_cache
    if _banks_cache is None:
        try:
            from .. import enablebanking
            _banks_cache = enablebanking.get_banks()
        except Exception as e:
            logger.error("Failed to fetch banks: %s", e)
            resp = jsonify([])
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp
    resp = jsonify(_banks_cache)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_sync_times():
    sync_time = config.SYNC_TIME or "06:00"
    frequency = int(getattr(config, 'SYNC_FREQUENCY', '24') or '24')
    if frequency == 0:
        return "Manual only"
    h, m = int(sync_time.split(":")[0]), int(sync_time.split(":")[1])
    times = []
    for i in range(0, 24, frequency):
        t_h = (h + i) % 24
        times.append(f"{t_h:02d}:{m:02d}")
    return ", ".join(times)

def _get_days_left():
    from .. import enablebanking
    return enablebanking.check_token_expiry()

def _start_scheduler_if_ready():
    if config.is_configured():
        try:
            from ..scheduler import start as start_scheduler
            threading.Thread(target=start_scheduler, daemon=True).start()
        except Exception as e:
            logger.warning("Could not start scheduler: %s", e)

def start(host="0.0.0.0", port=3000):
    _start_scheduler_if_ready()
    app.run(host=host, port=port, debug=False, use_reloader=False)
