import smtplib
import logging
import ssl
import requests
from email.mime.text import MIMEText
from . import config

logger = logging.getLogger(__name__)

_unsubscribed_cache = {}

def _as_bool(value, default=True) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() not in ("0", "false", "no", "off", "none")


def _smtp_security() -> str:
    value = (config.SMTP_SECURITY or "starttls").strip().lower()
    aliases = {
        "plain": "none",
        "plaintext": "none",
        "off": "none",
        "false": "none",
        "0": "none",
        "tls": "ssl",
    }
    value = aliases.get(value, value)
    if value not in ("starttls", "ssl", "none"):
        logger.warning("Unknown SMTP_SECURITY '%s'; falling back to starttls.", value)
        return "starttls"
    return value


def _tls_context():
    if _as_bool(config.SMTP_TLS_VERIFY, True):
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def _is_unsubscribed(email: str) -> bool:
    import time
    now = time.time()
    if email in _unsubscribed_cache and now - _unsubscribed_cache[email][1] < 3600:
        return _unsubscribed_cache[email][0]
    try:
        resp = requests.post("https://api.bridgebank.app/is-unsubscribed", json={"email": email}, timeout=5)
        result = resp.ok and resp.json().get("unsubscribed", False)
    except Exception:
        result = False
    _unsubscribed_cache[email] = (result, now)
    return result


def _smtp_host_for(email: str) -> str:
    domain = email.split("@")[-1].lower() if "@" in email else ""
    mapping = {
        "gmail.com":      "smtp.gmail.com",
        "googlemail.com": "smtp.gmail.com",
        "icloud.com":     "smtp.mail.me.com",
        "me.com":         "smtp.mail.me.com",
        "mac.com":        "smtp.mail.me.com",
        "outlook.com":    "smtp.office365.com",
        "hotmail.com":    "smtp.office365.com",
        "live.com":       "smtp.office365.com",
        "yahoo.com":      "smtp.mail.yahoo.com",
    }
    host = mapping.get(domain) or config.SMTP_HOST
    if not host:
        logger.warning("Could not determine SMTP host for '%s'. Set SMTP_HOST in your .env file or use a supported email provider (Gmail, iCloud, Outlook, Yahoo).", domain)
        host = f"smtp.{domain}"
    return host


def send(subject: str, body: str, raise_on_error: bool = False):
    smtp_auth = _as_bool(config.SMTP_AUTH, True)
    sender = config.SMTP_FROM or config.SMTP_USER
    host = _smtp_host_for(config.SMTP_USER) if config.SMTP_USER else config.SMTP_HOST
    if not config.NOTIFY_EMAIL or not sender or not host:
        msg = "SMTP settings not configured. Set up notifications in the Bridge Bank web UI."
        if raise_on_error:
            raise RuntimeError(msg)
        logger.warning("Email not sent (%s) — %s", subject, msg)
        return
    if smtp_auth and (not config.SMTP_USER or not config.SMTP_PASSWORD):
        msg = "SMTP credentials not configured. Set up notifications in the Bridge Bank web UI."
        if raise_on_error:
            raise RuntimeError(msg)
        logger.warning("Email not sent (%s) — %s", subject, msg)
        return
    if _is_unsubscribed(config.NOTIFY_EMAIL):
        logger.info("Skipping email for unsubscribed %s: %s", config.NOTIFY_EMAIL, subject)
        return
    mime = MIMEText(body)
    mime["Subject"] = subject
    mime["From"]    = sender
    mime["To"]      = config.NOTIFY_EMAIL
    try:
        port = int(config.SMTP_PORT or 587)
        security = _smtp_security()
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, context=_tls_context())
        else:
            smtp = smtplib.SMTP(host, port)
        with smtp as s:
            if security == "starttls":
                s.starttls(context=_tls_context())
            if smtp_auth:
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
            s.sendmail(sender, config.NOTIFY_EMAIL, mime.as_string())
        logger.info("Email sent: %s", subject)
    except Exception as e:
        logger.warning("Failed to send email: %s", e)
        if raise_on_error:
            raise RuntimeError(_friendly_smtp_error(e)) from e


def _friendly_smtp_error(e):
    """Convert SMTP exceptions to human-readable messages."""
    msg = str(e).lower()
    if "authentication failed" in msg or "535" in msg:
        return "Wrong password. Check your app-specific password and try again."
    if "username and password not accepted" in msg:
        return "Wrong email or password. Check your credentials and try again."
    if "connection refused" in msg or "errno 111" in msg:
        return "Could not connect to the email server. Check your email address."
    if "timed out" in msg or "timeout" in msg:
        return "Email server did not respond. Try again in a moment."
    if "relay" in msg or "sender" in msg:
        return "Your email provider rejected the message. Make sure the 'send from' address is correct."
    return f"Email failed: {e}"


def send_success(tx_count: int, details: list = None):
    if config.NOTIFY_ON in ("errors", "never"):
        return
    body = f"Sync completed successfully. {tx_count} transaction(s) imported."
    if details:
        body += "\n\n" + "\n".join(f"  ✓ {d}" for d in details)
    send("Bridge Bank: sync complete", body)


def send_failure(message: str):
    if config.NOTIFY_ON == "never":
        return
    send(
        "Bridge Bank: sync failed",
        f"Sync failed with the following error:\n\n{message}\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} to check your configuration."
    )


def send_partial(successes: list, errors: list):
    if config.NOTIFY_ON == "never":
        return
    lines = []
    for s in successes:
        lines.append(f"  ✓ {s}")
    for e in errors:
        lines.append(f"  ✗ {e}")
    body = "Sync finished with some errors:\n\n" + "\n".join(lines) + f"\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} to check your configuration."
    send("Bridge Bank: sync partially complete", body)


def send_trial_expiry_warning(days_left: int):
    send(
        f"Bridge Bank: trial expires in {days_left} day{'s' if days_left != 1 else ''}",
        f"Your Bridge Bank free trial expires in {days_left} day{'s' if days_left != 1 else ''}.\n\nPurchase a licence at https://bridgebank.app to keep syncing your transactions."
    )


def send_trial_expired():
    send(
        "Bridge Bank: trial expired",
        f"Your Bridge Bank free trial has expired. Syncing is paused until a licence is activated.\n\nPurchase a licence at https://bridgebank.app to resume syncing your transactions."
    )


def send_session_expiry_warning(days_left: int):
    send(
        f"Bridge Bank: bank session expires in {days_left} days",
        f"Your Enable Banking session expires in {days_left} days.\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} and go to the Bank page to re-authorise."
    )
