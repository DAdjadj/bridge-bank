import schedule
import time
import logging
import threading
from datetime import datetime, timedelta, timezone
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

def start():
    sync_time = config.SYNC_TIME or "06:00"
    frequency = int(getattr(config, 'SYNC_FREQUENCY', '24') or '24')

    if frequency == 0:
        logger.info("Scheduler disabled (manual only mode)")
        return

    logger.info("Scheduler starting. Sync at %s, every %dh", sync_time, frequency)

    if frequency == 24:
        schedule.every().day.at(sync_time).do(_run_sync)
    else:
        h, m = _parse_time(sync_time)
        times = []
        for i in range(0, 24, frequency):
            t_h = (h + i) % 24
            times.append(f"{t_h:02d}:{m:02d}")
        for t in times:
            schedule.every().day.at(t).do(_run_sync)
        logger.info("Sync times: %s", ", ".join(times))

    if _should_catchup(frequency):
        logger.info("Catch-up sync needed. Running now.")
        threading.Thread(target=sync.run, daemon=True).start()

    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    logger.info("Scheduler running.")
