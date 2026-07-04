#!/usr/bin/env python3
import logging
import os
from logging.handlers import RotatingFileHandler
from app import config
from app.web.server import start

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Also log to a rotating file in /data so the "Download logs" button on the
# Status page works without needing the docker CLI or a mounted docker socket.
LOG_FILE = "/data/bridge-bank.log"
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    _file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=2)
    _file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(_file_handler)
except Exception as e:
    logging.warning("Could not open log file %s: %s", LOG_FILE, e)

# ---------------------------------------------------------------------------
# Monkey-patch actualpy to fix SQLite syntax error with Actual Budget >= 26.3.0
# Bug: apply_change passes Column objects as keys in the ON CONFLICT SET clause,
# which causes SQLAlchemy to emit table-qualified names (e.g. custom_reports.tombstone)
# that are invalid in SQLite's ON CONFLICT DO UPDATE SET.
# Fix: convert Column keys to plain column-name strings for the set_ clause.
# Upstream: https://github.com/bvanelli/actualpy/issues (to be reported)
# ---------------------------------------------------------------------------
def _patch_actualpy():
    try:
        import actual.database as _adb
        import actual as _actual_mod
        from sqlalchemy import Column
        from sqlalchemy.dialects.sqlite import insert

        def _patched_apply_change(session, table, table_id, values):
            set_dict = {
                (col.name if isinstance(col, Column) else col): val
                for col, val in values.items()
            }
            insert_stmt = (
                insert(table)
                .values({"id": table_id, **values})
                .on_conflict_do_update(index_elements=["id"], set_=set_dict)
            )
            session.exec(insert_stmt)

        # Patch both the defining module and the importing module so the name
        # resolves to the patched version regardless of how it was imported.
        _adb.apply_change = _patched_apply_change
        if hasattr(_actual_mod, 'apply_change'):
            _actual_mod.apply_change = _patched_apply_change
        logging.getLogger(__name__).info("actualpy apply_change patched successfully")
    except Exception as e:
        logging.getLogger(__name__).warning("Failed to patch actualpy: %s", e)

_patch_actualpy()

if __name__ == "__main__":
    config._load()
    start(host="0.0.0.0", port=3000)
