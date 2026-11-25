"""The lines behind the Diagnostics page.

note(area, text) always writes a line; detail(area, text) only while that
area's detailed switch is on (24 hours at most). Both write a tagged line
into the app log that main.py keeps in /data/bridge-bank.log, so Download log
and support see them too:

    [diag] 2026-11-25T08:00:42Z Sync: Done: 3 accounts, 14 new, 42 s

Callers say what happened in counts, codes and times. Every line still goes
through log_redact and loses URLs, IP addresses and email addresses here, so
a slip can't put an IBAN, a key or a server address in the log.

The switches live in the settings table, which the web pages and the
scheduler share (they run in one process). No Flask here, so tests run
without it.
"""
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone

from .log_redact import sanitize_logs

logger = logging.getLogger("app.diag")
# Written whatever level the root logger is at: these lines are the point.
logger.setLevel(logging.INFO)

TAG = "[diag]"
AREAS = ("App", "Sync", "Bank", "Actual", "Email", "License", "Error")
# Areas with a detailed switch, in page order: (title, what it adds).
DETAILED = {
    "Bank": ("Bank connection", "Each Enable Banking request and its answer code"),
    "Actual": ("Writing to Actual Budget", "Matching, rules and transfers, as counts"),
    "Email": ("Email", "Each mail sent and the server's answer"),
    "License": ("License and updates", "Each license and update check and its answer code"),
}
DETAIL_LASTS = 24 * 3600

_SWITCHES_KEY = "diag_detailed"
_CLEARED_KEY = "diag_cleared_at"

_lock = threading.Lock()
_switches = None          # {area: on-since epoch seconds}
_last_said = {}


def _db():
    from . import db
    return db


# ---------------------------------------------------------------- redaction

_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")


def safe(text):
    """One line, no addresses, run through the log download's redaction."""
    text = re.sub(r"\s+", " ", str(text)).strip()
    text = _URL.sub("[address]", text)
    text = _EMAIL.sub("[email]", text)
    text = _IPV4.sub("[address]", text)
    return sanitize_logs(text)


# ---------------------------------------------------------------- writing

def line(area, text, at=None):
    at = at or datetime.now(timezone.utc)
    return f"{TAG} {at.strftime('%Y-%m-%dT%H:%M:%SZ')} {area}: {safe(text)}"


def note(area, text):
    """A line that is always kept. Never raises."""
    try:
        if area not in AREAS:
            area = "App"
        logger.info(line(area, text))
    except Exception:
        pass


def problem(area, text):
    """An error line, shown under Errors: 'Error: Bank: ING HTTP 429'."""
    note("Error", f"{area}: {text}")


def detail(area, text):
    """A line kept only while this area's detailed log is on."""
    if is_detailed(area):
        note(area, text)


def note_change(subject, area, text):
    """A note only when it says something new for this subject, for checks
    that run on every page load. Repeats still go to the detailed log."""
    if _last_said.get(subject) == text:
        detail(area, text)
        return
    _last_said[subject] = text
    note(area, text)


# ---------------------------------------------------------------- switches

def _load():
    global _switches
    if _switches is None:
        try:
            raw = json.loads(_db().get_setting(_SWITCHES_KEY) or "{}")
            _switches = {a: float(t) for a, t in raw.items() if a in DETAILED}
        except Exception:
            _switches = {}
    return _switches


def detailed_until(area, now=None):
    """Epoch seconds when this area's detailed log turns itself off, or None."""
    try:
        since = _load().get(area)
    except Exception:
        return None
    now = time.time() if now is None else now
    if not since or now - since >= DETAIL_LASTS:
        return None
    return since + DETAIL_LASTS


def is_detailed(area, now=None):
    return detailed_until(area, now) is not None


def set_detailed(area, on, now=None):
    global _switches
    if area not in DETAILED:
        raise ValueError(f"No detailed log for {area!r}")
    with _lock:
        switches = dict(_load())
        if on:
            switches[area] = time.time() if now is None else now
        else:
            switches.pop(area, None)
        _switches = switches
        try:
            _db().set_setting(_SWITCHES_KEY, json.dumps(switches))
        except Exception:
            pass
    note("App", f"Detailed log {'on' if on else 'off'}: {DETAILED[area][0]}")


def reset_cache():
    """For tests, and after the settings table is emptied."""
    global _switches
    _switches = None
    _last_said.clear()


# ---------------------------------------------------------------- clearing

def cleared_at():
    try:
        return float(_db().get_setting(_CLEARED_KEY) or 0)
    except Exception:
        return 0.0


def clear(now=None):
    """Hide every line written so far. The log file itself stays whole for
    support; only what the page shows starts again from now."""
    _db().set_setting(_CLEARED_KEY, str(time.time() if now is None else now))


# ---------------------------------------------------------------- reading

_DIAG_LINE = re.compile(r"\[diag\] (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (" + "|".join(AREAS) + r"): (.*)$")


def parse(text, since=0.0, limit=2000):
    """Diag lines in text, newest first: [(epoch, area, text)]. Lines before
    `since` (the Clear time) are left out."""
    out = []
    # Newest first, and among lines in the same second, the later one first.
    for raw in reversed(text.splitlines()):
        m = _DIAG_LINE.search(raw)
        if not m:
            continue
        try:
            at = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
        if at < since:
            continue
        out.append((at, m.group(2), safe(m.group(3))))
    out.sort(key=lambda e: e[0], reverse=True)
    return out[:limit]


def _zone(tz_name):
    if tz_name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(tz_name)
        except Exception:
            pass
    return timezone.utc


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _clock(dt, seconds):
    hour = dt.hour % 12 or 12
    ampm = "AM" if dt.hour < 12 else "PM"
    return f"{hour}:{dt.minute:02d}:{dt.second:02d} {ampm}" if seconds else f"{hour}:{dt.minute:02d} {ampm}"


def format_time(epoch, tz_name="", seconds=True):
    """'25 Nov 2026 8:00:42 AM' in the person's time zone."""
    dt = datetime.fromtimestamp(epoch, _zone(tz_name))
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year} {_clock(dt, seconds)}"


def format_when(epoch, tz_name="", now=None):
    """'8:00 PM', '8:00 PM tomorrow', '8:00 PM yesterday' or a full date."""
    zone = _zone(tz_name)
    dt = datetime.fromtimestamp(epoch, zone)
    today = datetime.fromtimestamp(time.time() if now is None else now, zone).date()
    days = (dt.date() - today).days
    clock = _clock(dt, False)
    if days == 0:
        return clock
    if days == 1:
        return f"{clock} tomorrow"
    if days == -1:
        return f"{clock} yesterday"
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year} {clock}"


def clock_text(hh_mm):
    """'20:00' -> '8:00 PM'."""
    try:
        h, m = (int(p) for p in str(hh_mm).split(":")[:2])
    except ValueError:
        return str(hh_mm)
    return f"{h % 12 or 12}:{m:02d} {'AM' if h < 12 else 'PM'}"


def format_date(epoch, tz_name=""):
    dt = datetime.fromtimestamp(epoch, _zone(tz_name))
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year}"
