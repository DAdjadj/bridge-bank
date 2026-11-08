"""Keep SQL that Bridge Bank didn't write inside the one database it was meant for.

Actual's schema migrations come from the Actual server as SQL text, and
Bridge Bank runs them on its local copy of the budget. Plain SQLite lets
such text ATTACH any other file the container can reach (Bridge Bank's own
instance.db with the Enable Banking key, for one) or write a new one with
VACUUM INTO. Real Actual migrations never do either, so both are refused:
a migration that tries fails the budget load instead of touching other files.

Standard library only, so the test runs without actualpy.
"""
import sqlite3


def _deny_attach(action, *_):
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def confine_to_main_database(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Refuse ATTACH and DETACH (and so VACUUM INTO) on this connection."""
    # Python 3.11+ can also lower the number of databases that may be
    # attached to none, which SQLite enforces even if the authorizer were lost.
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_ATTACHED"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
    conn.set_authorizer(_deny_attach)
    return conn
