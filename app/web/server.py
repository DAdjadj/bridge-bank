import logging
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify
from .. import config, db, licence, sync

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "bridge-bank-secret"

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
        return redirect(url_for("setup_licence"))
    if not config.is_connected():
        return redirect(url_for("connect"))
    return redirect(url_for("status"))

# ---------------------------------------------------------------------------
# Setup step 1: Licence
# ---------------------------------------------------------------------------

@app.route("/setup", methods=["GET", "POST"])
def setup_licence():
    error = None
    if request.method == "POST":
        key = request.form.get("licence_key", "").strip()
        result = licence.activate(key)
        if not result["valid"] and not result.get("offline"):
            error = result["error"] or "Invalid licence key."
        else:
            config.set("LICENCE_KEY", key)
            return redirect(url_for("setup_actual"))
    return render_template("setup_licence.html",
        error=error,
        licence_key=config.LICENCE_KEY,
        active="licence",
    )

# ---------------------------------------------------------------------------
# Setup step 2: Enable Banking
# ---------------------------------------------------------------------------

@app.route("/setup/bank", methods=["GET", "POST"])
def setup_bank():
    error = None
    if request.method == "POST":
        app_id   = request.form.get("eb_app_id", "").strip()
        psu_type = request.form.get("eb_psu_type", "personal").strip()
        if not app_id:
            error = "Application ID is required."
        else:
            config.set("EB_APPLICATION_ID", app_id)
            config.set("EB_PSU_TYPE", psu_type)
            return redirect(url_for("setup_actual"))
    return render_template("setup_bank.html",
        error=error,
        eb_app_id=config.EB_APPLICATION_ID,
        eb_psu_type=config.EB_PSU_TYPE,
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
            _start_scheduler_if_ready()
            return redirect(url_for("connect"))
    return render_template("setup_notifications.html",
        error=error,
        notify_email=config.NOTIFY_EMAIL,
        smtp_user=config.SMTP_USER,
        smtp_password=config.SMTP_PASSWORD,
        holder_name=config.ACCOUNT_HOLDER_NAME,
        active="notifications",
    )

# ---------------------------------------------------------------------------
# Connect (bank OAuth)
# ---------------------------------------------------------------------------

@app.route("/connect", methods=["GET", "POST"])
def connect():
    error    = None
    auth_url = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "start":
            bank_name    = request.form.get("bank_name", "").strip()
            bank_country = request.form.get("bank_country", "").strip()
            if not bank_name or not bank_country:
                error = "Please select a bank."
            else:
                config.set("EB_BANK_NAME", bank_name)
                config.set("EB_BANK_COUNTRY", bank_country)
                try:
                    from .. import enablebanking
                    result   = enablebanking.start_auth(bank_name, bank_country)
                    auth_url = result["url"]
                except Exception as e:
                    error = f"Could not start bank connection: {e}"

        elif action == "cancel":
            db.set_setting("pending_session_id", "")
            return redirect(url_for("connect"))

    tokens     = _get_tokens()
    days_left  = _get_days_left()
    success    = request.args.get("success")
    return render_template("connect.html",
        error=error,
        success=success,
        auth_url=auth_url,
        tokens=tokens,
        days_left=days_left,
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
        ok = enablebanking.complete_auth(code=code, state=state)
        if ok:
            _start_scheduler_if_ready()
            return redirect(url_for("connect") + "?success=1")
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
        return redirect(url_for("setup_licence"))
    if not config.is_connected():
        return redirect(url_for("connect"))

    syncs     = db.get_recent_syncs(limit=15)
    days_left = _get_days_left()
    last_sync = db.get_last_sync()
    act_info  = licence.get_activation_info()

    licence_sync_failed = False
    instance_id = db.get_setting("licence_instance_id")
    if syncs and not instance_id:
        last = syncs[0]
        msg  = (last.get("message") or "").lower()
        if last.get("status") == "failure" and "licence" in msg:
            licence_sync_failed = True

    return render_template("status.html",
        syncs=syncs,
        days_left=days_left,
        last_sync=last_sync,
        bank_name=config.EB_BANK_NAME,
        actual_account=config.ACTUAL_ACCOUNT,
        sync_interval_hours=config.SYNC_INTERVAL_HOURS,
        notify_email=config.NOTIFY_EMAIL,
        activation_usage=act_info["usage"],
        activation_limit=act_info["limit"],
        licence_sync_failed=licence_sync_failed,
        licence_limit_reached=(licence_sync_failed and act_info["usage"] >= act_info["limit"] and act_info["limit"] > 0),
        active="status",
    )

# ---------------------------------------------------------------------------
# Licence deactivate
# ---------------------------------------------------------------------------

@app.route("/settings/deactivate", methods=["POST"])
def deactivate_licence():
    result = licence.deactivate()
    if result["success"]:
        config.set("LICENCE_KEY", "")
        return redirect(url_for("setup_licence"))
    return redirect(url_for("status"))

# ---------------------------------------------------------------------------
# Sync now
# ---------------------------------------------------------------------------

@app.route("/sync/now", methods=["POST"])
def sync_now():
    threading.Thread(target=sync.run, daemon=True).start()
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------
# Disconnect
# ---------------------------------------------------------------------------

@app.route("/disconnect", methods=["POST"])
def disconnect():
    db.set_setting("eb_session_id", "")
    db.set_setting("eb_account_uid", "")
    db.set_setting("eb_session_expiry", "")
    return redirect(url_for("connect"))

# ---------------------------------------------------------------------------
# Detect URL helper
# ---------------------------------------------------------------------------

@app.route("/api/detect-url")
def detect_url():
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    host   = request.headers.get("X-Forwarded-Host", request.host)
    return jsonify({"url": f"{scheme}://{host}"})

# ---------------------------------------------------------------------------
# Banks
# ---------------------------------------------------------------------------

_banks_cache = None

@app.route("/banks")
def banks():
    global _banks_cache
    if _banks_cache is None:
        try:
            from .. import enablebanking
            _banks_cache = enablebanking.get_banks_public()
        except Exception as e:
            logger.error("Failed to fetch banks: %s", e)
            return jsonify([])
    return jsonify(_banks_cache)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_tokens():
    session_id = db.get_setting("eb_session_id")
    if not session_id:
        return None
    return {
        "bank_name":    config.EB_BANK_NAME,
        "bank_country": config.EB_BANK_COUNTRY,
        "session_id":   session_id,
    }

def _get_days_left():
    exp = db.get_setting("eb_session_expiry")
    if not exp:
        return None
    try:
        from datetime import datetime, timezone
        expiry = datetime.fromisoformat(exp)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except Exception:
        return None

def _start_scheduler_if_ready():
    if config.is_configured():
        try:
            from ..scheduler import start as start_scheduler
            threading.Thread(target=start_scheduler, daemon=True).start()
        except Exception as e:
            logger.warning("Could not start scheduler: %s", e)

def start(host="0.0.0.0", port=3000):
    app.run(host=host, port=port, debug=False, use_reloader=False)
