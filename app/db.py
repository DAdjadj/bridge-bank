import sqlite3
import os

DB_PATH = "/data/instance.db"

def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _ensure_tables(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ran_at TEXT DEFAULT (datetime('now')),
            status TEXT,
            tx_count INTEGER DEFAULT 0,
            message TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bank_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            account_uid TEXT NOT NULL,
            bank_name TEXT NOT NULL,
            bank_country TEXT NOT NULL,
            actual_account TEXT NOT NULL,
            session_expiry TEXT,
            start_sync_date TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    # Add start_sync_date column if missing (migration)
    try:
        conn.execute("ALTER TABLE bank_accounts ADD COLUMN start_sync_date TEXT")
    except Exception:
        pass
    conn.commit()

    # Migrate legacy flat settings into bank_accounts table
    row = conn.execute("SELECT value FROM settings WHERE key = 'eb_session_id'").fetchone()
    if row and row["value"]:
        count = conn.execute("SELECT COUNT(*) FROM bank_accounts").fetchone()[0]
        if count == 0:
            sid = row["value"]
            uid_row = conn.execute("SELECT value FROM settings WHERE key = 'eb_account_uid'").fetchone()
            exp_row = conn.execute("SELECT value FROM settings WHERE key = 'eb_session_expiry'").fetchone()
            uid = uid_row["value"] if uid_row else ""
            exp = exp_row["value"] if exp_row else ""
            # Import config for legacy bank name / actual account
            try:
                from . import config
                bank_name = config.EB_BANK_NAME or "Unknown"
                bank_country = config.EB_BANK_COUNTRY or ""
                actual_account = config.ACTUAL_ACCOUNT or "Main"
            except Exception:
                bank_name = "Unknown"
                bank_country = ""
                actual_account = "Revolut"
            if uid:
                conn.execute(
                    "INSERT INTO bank_accounts (session_id, account_uid, bank_name, bank_country, actual_account, session_expiry) VALUES (?, ?, ?, ?, ?, ?)",
                    (sid, uid, bank_name, bank_country, actual_account, exp)
                )
                conn.commit()

def get_setting(key: str) -> str:
    with _conn() as conn:
        _ensure_tables(conn)
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else ""

def set_setting(key: str, value: str):
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value)
        )
        conn.commit()

def log_sync(status: str, tx_count: int = 0, message: str = ""):
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute(
            "INSERT INTO sync_log (status, tx_count, message) VALUES (?, ?, ?)",
            (status, tx_count, message)
        )
        conn.commit()

def get_recent_syncs(limit: int = 15) -> list:
    with _conn() as conn:
        _ensure_tables(conn)
        rows = conn.execute(
            "SELECT ran_at, status, tx_count, message FROM sync_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_sync_log_page(page: int = 1, per_page: int = 5) -> dict:
    with _conn() as conn:
        _ensure_tables(conn)
        total = conn.execute("SELECT COUNT(*) FROM sync_log").fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            "SELECT ran_at, status, tx_count, message FROM sync_log ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
        return {
            "syncs": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        }

def clear_sync_log():
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute("DELETE FROM sync_log")
        conn.commit()

def get_last_sync() -> str:
    with _conn() as conn:
        _ensure_tables(conn)
        row = conn.execute(
            "SELECT ran_at FROM sync_log WHERE status = 'success' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["ran_at"] if row else ""

def get_all_bank_accounts() -> list:
    with _conn() as conn:
        _ensure_tables(conn)
        rows = conn.execute(
            "SELECT * FROM bank_accounts ORDER BY created_at ASC"
        ).fetchall()
        return [dict(r) for r in rows]

def get_bank_account_count() -> int:
    with _conn() as conn:
        _ensure_tables(conn)
        return conn.execute("SELECT COUNT(*) FROM bank_accounts").fetchone()[0]

def add_bank_account(session_id: str, account_uid: str, bank_name: str, bank_country: str, actual_account: str, session_expiry: str = "", start_sync_date: str = ""):
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute(
            "INSERT INTO bank_accounts (session_id, account_uid, bank_name, bank_country, actual_account, session_expiry, start_sync_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, account_uid, bank_name, bank_country, actual_account, session_expiry, start_sync_date)
        )
        conn.commit()

def update_bank_account_field(account_id: int, field: str, value: str):
    allowed = {"start_sync_date", "session_id", "account_uid", "session_expiry", "actual_account"}
    if field not in allowed:
        raise ValueError(f"Field {field} is not updatable")
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute(f"UPDATE bank_accounts SET {field} = ? WHERE id = ?", (value, account_id))
        conn.commit()

def get_first_sync_date() -> str:
    with _conn() as conn:
        _ensure_tables(conn)
        row = conn.execute(
            "SELECT ran_at FROM sync_log ORDER BY id ASC LIMIT 1"
        ).fetchone()
        return row["ran_at"] if row else ""

def remove_bank_account(account_id: int):
    with _conn() as conn:
        _ensure_tables(conn)
        conn.execute("DELETE FROM bank_accounts WHERE id = ?", (account_id,))
        conn.commit()
