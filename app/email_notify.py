import smtplib
import logging
from email.mime.text import MIMEText
from . import config

logger = logging.getLogger(__name__)


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
    if not config.NOTIFY_EMAIL or not config.SMTP_USER or not config.SMTP_PASSWORD:
        msg = "SMTP credentials not configured. Set up notifications in the Bridge Bank web UI."
        if raise_on_error:
            raise RuntimeError(msg)
        logger.warning("Email not sent (%s) — %s", subject, msg)
        return
    mime = MIMEText(body)
    mime["Subject"] = subject
    mime["From"]    = config.SMTP_FROM or config.SMTP_USER
    mime["To"]      = config.NOTIFY_EMAIL
    try:
        host = _smtp_host_for(config.SMTP_USER)
        port = int(config.SMTP_PORT or 587)
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
            s.sendmail(config.SMTP_FROM or config.SMTP_USER, config.NOTIFY_EMAIL, mime.as_string())
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


def send_success(tx_count: int):
    if config.NOTIFY_ON == "errors":
        return
    send(
        "Bridge Bank: sync complete",
        f"Sync completed successfully. {tx_count} transaction(s) imported."
    )


def send_failure(message: str):
    send(
        "Bridge Bank: sync failed",
        f"Sync failed with the following error:\n\n{message}\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} to check your configuration."
    )


def send_partial(successes: list, errors: list):
    lines = []
    for s in successes:
        lines.append(f"  ✓ {s}")
    for e in errors:
        lines.append(f"  ✗ {e}")
    body = "Sync finished with some errors:\n\n" + "\n".join(lines) + f"\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} to check your configuration."
    send("Bridge Bank: sync partially complete", body)


def send_session_expiry_warning(days_left: int):
    send(
        f"Bridge Bank: bank session expires in {days_left} days",
        f"Your Enable Banking session expires in {days_left} days.\n\nOpen Bridge Bank at {config.BRIDGE_BANK_URL} and go to the Bank page to re-authorise."
    )
