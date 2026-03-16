import schedule
import time
import logging
import threading
from datetime import datetime, timedelta, timezone
from . import config, db, sync

logger = logging.getLogger(__name__)

def _should_catchup() -> bool:
    last = db.get_last_sync()
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
        return (datetime.now(timezone.utc) - last_dt.replace(tzinfo=timezone.utc)) > timedelta(hours=20)
    except Exception:
        return False

def _run_sync():
    logger.info("Scheduled sync triggered at %s", datetime.now().isoformat())
    sync.run()

def start():
    logger.info("Scheduler starting. Daily sync at %s", config.SYNC_TIME)

    schedule.every().day.at(config.SYNC_TIME).do(_run_sync)

    if _should_catchup():
        logger.info("Last sync was >20 hours ago or never ran. Running catch-up sync.")
        threading.Thread(target=sync.run, daemon=True).start()

    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    logger.info("Scheduler running.")
