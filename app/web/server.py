import logging
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify
from .. import config, db, licence, sync

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "bridge-bank-secret"

CONTAINER_NAME = "bridge-bank"
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
        existing_pem = db.get_setting("eb_pem_content")
        if not app_id:
            error = "Application ID is required."
        elif not pem_content and not existing_pem:
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
        holder_name   = request.form.get("holder_name", "").strip()
        if not notify_email or not smtp_user or not smtp_password:
            error = "Notification email and sending credentials are required."
        else:
            config.set("NOTIFY_EMAIL", notify_email)
            config.set("SMTP_USER", smtp_user)
            config.set("SMTP_PASSWORD", smtp_password)
            config.set("ACCOUNT_HOLDER_NAME", holder_name)
            scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
            host   = request.headers.get("X-Forwarded-Host", request.host)
            config.set("BRIDGE_BANK_URL", f"{scheme}://{host}")
            return redirect(url_for("setup_sync"))
    return render_template("setup_notifications.html",
        error=error,
        notify_email=config.NOTIFY_EMAIL,
        smtp_user=config.SMTP_USER,
        smtp_password=config.SMTP_PASSWORD,
        holder_name=config.ACCOUNT_HOLDER_NAME,
        active="notifications",
    )

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
        return redirect(url_for("connect"))
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
                db.set_setting("eb_pem_content", pem_content)
                db.set_setting("eb_app_id", app_id)
                config.set("EB_APPLICATION_ID", app_id)
                return redirect(url_for("connect"))

        elif action == "start":
            bank_name      = request.form.get("bank_name", "").strip()
            bank_country   = request.form.get("bank_country", "").strip()
            actual_account = request.form.get("actual_account", "").strip()
            if not bank_name or not bank_country:
                error = "Please select a bank."
            elif not actual_account:
                error = "Please enter the Actual Budget account name."
            else:
                config.set("EB_BANK_NAME", bank_name)
                config.set("EB_BANK_COUNTRY", bank_country)
                db.set_setting("pending_actual_account", actual_account)
                db.set_setting("pending_bank_name", bank_name)
                db.set_setting("pending_bank_country", bank_country)
                try:
                    from .. import enablebanking
                    result   = enablebanking.start_auth(bank_name, bank_country)
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
            resp = _requests.post("https://api.klartion.com/info", json={"license_key": key}, timeout=5)
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
            resp = _requests.post("https://api.klartion.com/info", json={"license_key": key}, timeout=5)
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
        active="connect",
    )

# ---------------------------------------------------------------------------
# OAuth callback
# ---------------------------------------------------------------------------

@app.route("/callback")
def callback():
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error")
    if error or not code:
        return redirect(url_for("connect") + "?error=auth_failed")
    try:
        from .. import enablebanking
        result = enablebanking.complete_auth(code=code, state=state)
        if result:
            # Retrieve pending info
            actual_account = db.get_setting("pending_actual_account") or config.ACTUAL_ACCOUNT
            bank_name      = db.get_setting("pending_bank_name") or config.EB_BANK_NAME
            bank_country   = db.get_setting("pending_bank_country") or config.EB_BANK_COUNTRY

            # Save to bank_accounts table
            db.add_bank_account(
                session_id=result["session_id"],
                account_uid=result["account_uid"],
                bank_name=bank_name,
                bank_country=bank_country,
                actual_account=actual_account,
                session_expiry=result.get("valid_until", ""),
            )

            # Clear pending settings
            db.set_setting("pending_actual_account", "")
            db.set_setting("pending_bank_name", "")
            db.set_setting("pending_bank_country", "")
            db.set_setting("pending_session_state", "")
            db.set_setting("pending_session_valid_until", "")

            _start_scheduler_if_ready()
            threading.Thread(target=sync.run, daemon=True).start()
            return redirect(url_for("status"))
        else:
            return redirect(url_for("connect") + "?error=auth_failed")
    except Exception as e:
        logger.error("Callback failed: %s", e)
        return redirect(url_for("connect") + "?error=" + str(e))

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
    streak_rows = db.get_recent_syncs(limit=100)
    streak = 0
    for r in streak_rows:
        if r["status"] == "success":
            streak += 1
        else:
            break
    total_tx = sum(r.get("tx_count", 0) for r in db.get_recent_syncs(limit=9999))

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
        notify_email=config.NOTIFY_EMAIL,
        activation_usage=act_info["usage"],
        activation_limit=act_info["limit"],
        license_sync_failed=license_sync_failed,
        license_limit_reached=(license_sync_failed and act_info["usage"] >= act_info["limit"] and act_info["limit"] > 0),
        page=log_data["page"],
        total_pages=log_data["total_pages"],
        active="status",
        update_mode=db.get_setting("update_mode"),
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

@app.route("/sync/now", methods=["POST"])
def sync_now():
    threading.Thread(target=sync.run, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/sync/reset", methods=["POST"])
def sync_reset():
    import json, os
    state_file = "/data/state.json"
    if os.path.exists(state_file):
        with open(state_file) as f:
            state = json.load(f)
        state.pop("last_sync_date", None)
        for key in list(state.get("accounts", {}).keys()):
            state["accounts"][key].pop("last_sync_date", None)
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    db.clear_sync_log()
    return redirect(url_for("setup_sync"))

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
        manifest_resp = _req.head(
            f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.docker.distribution.manifest.v2+json"},
            timeout=5
        )
        remote_digest = manifest_resp.headers.get("Docker-Content-Digest", "")
        local_digest = subprocess.run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", IMAGE_NAME],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        local_sha = local_digest.split("@")[-1] if "@" in local_digest else ""
        return jsonify({"available": remote_digest != local_sha and remote_digest != ""})
    except Exception:
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
        if "Image is up to date" in pull.stdout or "Image is up to date" in pull.stderr:
            return jsonify({"up_to_date": True})
        subprocess.Popen(
            ["sh", "-c", "sleep 2 && cd /compose && docker compose up -d"],
            start_new_session=True
        )
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
    app.run(host=host, port=port, debug=False, use_reloader=False)
