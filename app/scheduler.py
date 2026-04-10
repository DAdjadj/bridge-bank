import schedule
import time
import logging
import threading
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from . import config, db, sync

logger = logging.getLogger(__name__)

def _should_catchup(frequency_hours) -> bool:
    last = db.get_last_sync()
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
        return (datetime.now(timezone.utc) - last_dt.replace(tzinfo=timezone.utc)) > timedelta(hours=frequency_hours - 1)
    except Exception:
        return False

def _run_sync():
    logger.info("Scheduled sync triggered at %s", datetime.now().isoformat())
    sync.run()

def _parse_time(time_str):
    """Parse HH:MM string into hours and minutes."""
    parts = time_str.split(":")
    return int(parts[0]), int(parts[1])

def _local_times_to_utc(sync_time_str, frequency, tz_name):
    """Convert user's local sync times to UTC, accounting for DST."""
    h, m = _parse_time(sync_time_str)
    local_times = []
    for i in range(0, 24, frequency):
        local_times.append(f"{(h + i) % 24:02d}:{m:02d}")

    if not tz_name:
        return local_times

    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        logger.warning("Invalid timezone %r, using times as-is", tz_name)
        return local_times

    today = datetime.now(tz).date()
    utc_times = []
    for lt in local_times:
        lh, lm = _parse_time(lt)
        local_dt = datetime(today.year, today.month, today.day, lh, lm, tzinfo=tz)
        utc_dt = local_dt.astimezone(ZoneInfo("UTC"))
        utc_times.append(f"{utc_dt.hour:02d}:{utc_dt.minute:02d}")

    return utc_times

_started = False

def start():
    global _started
    sync_time = config.SYNC_TIME or "06:00"
    frequency = int(getattr(config, 'SYNC_FREQUENCY', '24') or '24')
    tz_name = getattr(config, 'TIMEZONE', '') or ''

    # Clear any previously scheduled jobs (e.g. if settings changed)
    schedule.clear()

    if frequency == 0:
        logger.info("Scheduler disabled (manual only mode)")
        return

    logger.info("Scheduler starting. Sync at %s, every %dh, timezone %s",
                sync_time, frequency, tz_name or "UTC")

    utc_times = _local_times_to_utc(sync_time, frequency, tz_name)

    if tz_name:
        logger.info("Local times: %s -> UTC times: %s",
                     ", ".join(_local_times_to_utc(sync_time, frequency, "")[:len(utc_times)]),
                     ", ".join(utc_times))

    for t in utc_times:
        schedule.every().day.at(t).do(_run_sync)

    if len(utc_times) > 1:
        logger.info("Sync times: %s", ", ".join(utc_times))

    if _should_catchup(frequency):
        logger.info("Catch-up sync needed. Running now.")
        threading.Thread(target=sync.run, daemon=True).start()

    # Only start the loop thread once
    if not _started:
        _started = True
        def loop():
            while True:
                schedule.run_pending()
                time.sleep(60)
        threading.Thread(target=loop, daemon=True).start()

    logger.info("Scheduler running.")
