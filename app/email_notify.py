import datetime
import re
import smtplib
import logging
import ssl
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from . import config, email_design as design

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


def _smtp_host() -> str:
    return _smtp_host_for(config.SMTP_USER) if config.SMTP_USER else config.SMTP_HOST


def build_message(subject: str, body: str, html: str = None, sender: str = "", to: str = ""):
    """The email itself: plain text alone, or plain text plus HTML for mail apps that show it."""
    if html is None:
        mime = MIMEText(body)
    else:
        mime = MIMEMultipart("alternative")
        mime.attach(MIMEText(body, "plain", "utf-8"))
        mime.attach(MIMEText(html, "html", "utf-8"))
    mime["Subject"] = subject
    mime["From"]    = sender
    mime["To"]      = to
    return mime


def send(subject: str, body: str, raise_on_error: bool = False, html: str = None):
    smtp_auth = _as_bool(config.SMTP_AUTH, True)
    sender = config.SMTP_FROM or config.SMTP_USER
    host = _smtp_host()
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
    mime = build_message(subject, body, html, sender, config.NOTIFY_EMAIL)
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




# ═══════════════════════════════════════════════════════════════════
# The alerts
#
# Each alert is described once as content and email_design renders it
# twice: HTML in Bridge Bank's blueprint look, and the plain-text part.
# build_* returns (subject, content) so every alert can be rendered and
# checked without sending anything.
# ═══════════════════════════════════════════════════════════════════

SUPPORT = "support@bridgebank.app"
PRICING_URL = "https://bridgebank.app/#pricing"

_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_MONTHS = ["January", "February", "March", "April", "May", "June", "July",
           "August", "September", "October", "November", "December"]


def _now() -> datetime.datetime:
    """Now in the time zone set on the Sync page (UTC when none is set)."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.datetime.now(ZoneInfo(config.TIMEZONE or "UTC"))
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc)


def _day_long(d) -> str:   # "Thursday, October 29"
    return f"{_DAYS[d.weekday()]}, {_MONTHS[d.month - 1]} {d.day}"


def _day_short(d) -> str:  # "Oct 29"
    return f"{_MONTHS[d.month - 1][:3]} {d.day}"


def _when(dt) -> str:      # "Oct 26, 7:00 AM"
    return f"{_day_short(dt)}, {dt.hour % 12 or 12}:{dt:%M} {'AM' if dt.hour < 12 else 'PM'}"


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _app_url(path: str = "") -> str:
    base = (config.BRIDGE_BANK_URL or "").strip().rstrip("/")
    return base + path if base else ""


def _page_link(label: str, path: str) -> str:
    url = _app_url(path)
    return f"[{label}]({url})" if url else label


def _open_button(label: str = "Open Bridge Bank", path: str = "") -> dict:
    return {"label": label, "href": _app_url(path)}


def _reason(kind: str) -> str:
    notifications = _page_link("Notifications page", "/setup/notifications")
    if kind == "every-sync":
        return f"Sent by your Bridge Bank after every sync. To hear only about problems, choose Errors only on its {notifications}."
    if kind == "problem":
        return f"Sent by your Bridge Bank when a sync has a problem. You can change this on its {notifications}."
    return f"Sent by your Bridge Bank to the address on its {notifications}."


_TRANSFERS = re.compile(r"^Internal transfers: (\d+) linked$")
_COUNT = re.compile(r"^(\d+) transactions?$")


def _split(line: str):
    """'ING (NL) → Checking: 5 transactions' into ('ING (NL) → Checking', '5 transactions').

    Errors carry colons of their own, so the split is at the first ': ' after
    the arrow when there is one."""
    line = line.strip().lstrip("✓✗").strip()
    start = line.find("→")
    idx = line.find(": ", start if start >= 0 else 0)
    if idx <= 0:
        return "", line
    return line[:idx].strip(), line[idx + 2:].strip()


def _sentence(s: str) -> str:
    s = (s or "").strip()
    return s[:1].upper() + s[1:] if s else s


def _account_rows(successes: list, errors: list):
    """Rows for the parts list, plus (accounts synced, accounts in total)."""
    rows, ok, total = [], 0, 0
    for line in successes or []:
        m = _TRANSFERS.match(line.strip())
        if m:
            rows.append({"name": "Internal transfers", "result": f"{m.group(1)} linked", "ok": True})
            continue
        name, rest = _split(line)
        c = _COUNT.match(rest)
        rows.append({"name": name or rest, "result": f"{c.group(1)} new" if c else (rest or "Synced"), "ok": True})
        ok += 1
        total += 1
    for line in errors or []:
        name, rest = _split(line)
        rows.append({"name": name, "result": "Failed", "detail": _sentence(rest), "ok": False})
        total += 1
    # Accounts first, failed ones on top, transfers last.
    rows.sort(key=lambda r: (r["name"] == "Internal transfers", r["ok"]))
    return rows, ok, total


_TRY_STEPS = [
    "Open the Status page in Bridge Bank. Its sync log shows each step.",
    "If a bank asks to be re-authorized, click Re-authorize on the Bank page.",
    f"Still stuck? Click Download logs on the Status page and send them to [{SUPPORT}](mailto:{SUPPORT}).",
]


def build_success(tx_count: int, details: list = None):
    now = _now()
    rows, ok, total = _account_rows(details or [], [])
    every = "Your account synced" if total == 1 else "Every account synced"
    if tx_count:
        lede = f"{every}, and {_plural(tx_count, 'new transaction is', 'new transactions are')} in Actual Budget."
    else:
        lede = f"{every}. There were no new transactions this time."
    return "Bridge Bank: sync complete", {
        "subject": "Bridge Bank: sync complete",
        "preheader": lede,
        "chip": f"Sync · {_when(now)}",
        "title": "Sync complete",
        "intro": [lede],
        "facts": [
            {"label": "Imported", "value": _plural(tx_count, "transaction", "transactions")},
            {"label": "Accounts", "value": f"{ok} of {total} synced" if total else "Synced"},
        ],
        "accounts": rows,
        "cta": _open_button(),
        "reason": _reason("every-sync"),
    }


def build_failure(message: str):
    now = _now()
    lines = [l for l in (message or "").splitlines() if l.strip()]
    per_account = bool(lines) and all(l.strip().startswith("✗") for l in lines)
    e = {
        "subject": "Bridge Bank: sync failed",
        "preheader": "Nothing was imported this time. Here is what went wrong.",
        "chip": f"Sync · {_when(now)}",
        "title": "Sync failed",
        "intro": ["Nothing was imported this time. Here is what went wrong."],
        "facts": [
            {"label": "Imported", "value": "0 transactions"},
        ],
        "steps_title": "What to try",
        "steps": _TRY_STEPS,
        "cta": _open_button(),
        "reason": _reason("problem"),
    }
    if per_account:
        e["accounts"], _, total = _account_rows([], lines)
        e["facts"].insert(1, {"label": "Accounts", "value": f"0 of {total} synced", "bad": True})
    else:
        e["facts"].insert(0, {"label": "Error", "value": _sentence((message or "Unknown error").strip()), "wide": True, "bad": True})
    return e["subject"], e


def build_partial(successes: list, errors: list):
    now = _now()
    rows, ok, total = _account_rows(successes, errors)
    added = 0
    for line in successes or []:
        c = _COUNT.match(_split(line)[1])
        if c and not _TRANSFERS.match(line.strip()):
            added += int(c.group(1))
    bad = total - ok
    title = "One account didn't sync" if bad == 1 else f"{bad} accounts didn't sync"
    if added:
        lede = f"The others synced, and {_plural(added, 'new transaction is', 'new transactions are')} in Actual Budget."
    else:
        lede = "The others synced, with no new transactions this time."
    return "Bridge Bank: sync partially complete", {
        "subject": "Bridge Bank: sync partially complete",
        "preheader": f"{title}. {lede}",
        "chip": f"Sync · {_when(now)}",
        "title": title,
        "intro": [lede],
        "facts": [
            {"label": "Imported", "value": _plural(added, "transaction", "transactions")},
            {"label": "Accounts", "value": f"{ok} of {total} synced"},
        ],
        "accounts": rows,
        "steps_title": "What to try",
        "steps": _TRY_STEPS,
        "cta": _open_button(),
        "reason": _reason("problem"),
    }


def _buy_after() -> list:
    return [f"Questions before you buy? Write to [{SUPPORT}](mailto:{SUPPORT})."]


def build_trial_expiry_warning(days_left: int):
    ends = _now().date() + datetime.timedelta(days=days_left)
    subject = f"Bridge Bank: trial expires in {_plural(days_left, 'day', 'days')}"
    title = "Your trial ends tomorrow" if days_left == 1 else f"Your trial ends in {days_left} days"
    return subject, {
        "subject": subject,
        "preheader": "A license keeps syncing running: one payment, no subscription.",
        "chip": f"Trial · ends {_day_short(ends)}",
        "title": title,
        "intro": ["When it ends, syncing to Actual Budget pauses. A license keeps it running: one payment, no subscription."],
        "facts": [
            {"label": "Ends", "value": _day_long(ends), "wide": True},
            {"label": "Then", "value": "Syncing pauses"},
            {"label": "Your setup", "value": "Saved"},
        ],
        "cta": {"label": "Buy Bridge Bank", "href": PRICING_URL,
                "sub": "Buy with the email address you started the trial with, and your trial key becomes a full license by itself. Nothing to re-enter."},
        "after": _buy_after(),
        "reason": _reason("account"),
    }


def build_trial_expired():
    return "Bridge Bank: trial expired", {
        "subject": "Bridge Bank: trial expired",
        "preheader": "Syncing is paused. Everything you set up is saved and starts again with a license.",
        "chip": "Trial ended",
        "title": "Your trial has ended",
        "intro": ["Syncing to Actual Budget is paused. Your bank connections and every setting are still saved, so a license picks up exactly where the trial stopped."],
        "facts": [
            {"label": "Syncing", "value": "Paused", "bad": True},
            {"label": "Your setup", "value": "Saved"},
        ],
        "cta": {"label": "Buy Bridge Bank", "href": PRICING_URL,
                "sub": "One payment, no subscription. Buy with the email address you started the trial with, and your trial key becomes a full license by itself."},
        "after": _buy_after(),
        "reason": _reason("account"),
    }


def build_session_expiry_warning(days_left: int, bank_name: str = None):
    bank = (bank_name or "").strip()
    ends = _now().date() + datetime.timedelta(days=max(days_left, 0))
    when = "today" if days_left <= 0 else "tomorrow" if days_left == 1 else f"in {days_left} days"
    subject = f"Bridge Bank: bank session expires {'today' if days_left <= 0 else 'in ' + _plural(days_left, 'day', 'days')}"
    return subject, {
        "subject": subject,
        "preheader": "Re-authorize it on the Bank page. It takes about a minute.",
        "chip": f"Bank · expires {_day_short(ends)}",
        "title": f"Your {bank or 'bank'} connection expires {when}",
        "intro": ["Banks ask you to approve Bridge Bank's access again from time to time. It takes about a minute, and syncing carries on as before."],
        "facts": [
            {"label": "Bank", "value": bank or "Your bank"},
            {"label": "Expires", "value": _day_long(ends), "wide": True},
            {"label": "After that", "value": "Syncing stops"},
        ],
        "steps_title": "Renew it in three steps",
        "steps": [
            f"Open Bridge Bank and go to the {_page_link('Bank page', '/bank')}.",
            f"Click Re-authorize under {bank or 'the bank'}.",
            "Sign in at your bank and approve access.",
        ],
        "cta": _open_button("Open the Bank page", "/bank"),
        "reason": _reason("account"),
    }


_NOTIFY_ON = {"all": "All syncs", "errors": "Errors only", "never": "Never"}


def build_test(notify_on: str = None):
    """The Notifications page's test email. The page can pass a choice it hasn't saved yet."""
    notify_on = (notify_on or config.NOTIFY_ON or "all").strip().lower()
    then = {
        "all": "From now on, the result of every sync arrives here, looking like this.",
        "errors": "When a sync has a problem, you'll hear about it here, looking like this.",
    }.get(notify_on, "")
    return "Bridge Bank: test email", {
        "subject": "Bridge Bank: test email",
        "preheader": "If you can read this, Bridge Bank's emails reach you.",
        "chip": "Test",
        "title": "Email alerts are working",
        "intro": [f"This is a test from your Bridge Bank. {then}".strip()],
        "facts": [
            {"label": "Sent to", "value": config.NOTIFY_EMAIL or "", "wide": True},
            {"label": "When to notify", "value": _NOTIFY_ON.get(notify_on, notify_on.title())},
            {"label": "Sent through", "value": _smtp_host() or "Not set"},
        ],
        "cta": _open_button(),
        "reason": _reason("account"),
    }


def _send(built, raise_on_error: bool = False):
    subject, e = built
    send(subject, design.render_text(e), raise_on_error=raise_on_error, html=design.render_html(e))


def send_success(tx_count: int, details: list = None):
    if config.NOTIFY_ON in ("errors", "never"):
        return
    _send(build_success(tx_count, details))


def send_failure(message: str):
    if config.NOTIFY_ON == "never":
        return
    _send(build_failure(message))


def send_partial(successes: list, errors: list):
    if config.NOTIFY_ON == "never":
        return
    _send(build_partial(successes, errors))


def send_trial_expiry_warning(days_left: int):
    _send(build_trial_expiry_warning(days_left))


def send_trial_expired():
    _send(build_trial_expired())


def send_session_expiry_warning(days_left: int, bank_name: str = None):
    _send(build_session_expiry_warning(days_left, bank_name))


def send_test(notify_on: str = None):
    """The Notifications page's test button: raises with a readable reason when sending fails."""
    _send(build_test(notify_on), raise_on_error=True)
