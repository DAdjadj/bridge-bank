"""Regression tests for the idempotent Actual migration patch.

Budgets migrated by the Actual web client can carry a schema change whose
migration id is absent from the budget's __migrations__ table (an earlier
Actual version applied it under a different id). actualpy then replays the
server's migration file and SQLite raises e.g.
'duplicate column name: show_trend_lines', aborting the whole sync. The patch
records-and-skips such already-applied migrations while still surfacing any
genuine migration failure. See app.sync._patch_idempotent_migrations.
"""
import pathlib
import sqlite3
import tempfile
import unittest

from sqlalchemy import create_engine

from actual import Actual
from app.sync import _patch_idempotent_migrations

TREND_FILE = "migrations/1780099200000_add_show_trend_lines_report_setting.sql"
TREND_SQL = (
    "BEGIN TRANSACTION;\n"
    "ALTER TABLE custom_reports ADD COLUMN show_trend_lines INTEGER DEFAULT 0;\n"
    "COMMIT;\n"
)


class _StubActual:
    """Minimal stand-in exposing what the patched run_migrations touches."""

    def __init__(self, data_dir, files):
        self._data_dir = pathlib.Path(data_dir)
        self._files = files
        self.engine = create_engine(f"sqlite:///{self._data_dir / 'db.sqlite'}")

    def data_file(self, name):
        return self._files[name].encode()


def _make_db(path, *, column_present, recorded_ids=()):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE __migrations__ (id INTEGER PRIMARY KEY);")
    cols = "id TEXT PRIMARY KEY, name TEXT"
    if column_present:
        cols += ", show_trend_lines INTEGER DEFAULT 0"
    conn.execute(f"CREATE TABLE custom_reports ({cols});")
    for mid in recorded_ids:
        conn.execute("INSERT INTO __migrations__ (id) VALUES (?);", (mid,))
    conn.commit()
    conn.close()


class MigrationIdempotencyTest(unittest.TestCase):
    def setUp(self):
        _patch_idempotent_migrations()
        # confirm the patch is actually installed on the class
        self.assertEqual(Actual.run_migrations.__name__, "_run_migrations")

    def _recorded(self, db_path):
        conn = sqlite3.connect(db_path)
        ids = {r[0] for r in conn.execute("SELECT id FROM __migrations__")}
        conn.close()
        return ids

    def test_duplicate_column_is_tolerated_and_recorded(self):
        """The exact production case: column exists, migration id unrecorded."""
        with tempfile.TemporaryDirectory() as d:
            db_path = pathlib.Path(d) / "db.sqlite"
            _make_db(db_path, column_present=True)
            stub = _StubActual(d, {TREND_FILE: TREND_SQL})
            # must not raise, despite the ALTER hitting an existing column
            Actual.run_migrations(stub, [TREND_FILE])
            # migration now recorded so it will not be replayed forever
            self.assertIn(1780099200000, self._recorded(db_path))

    def test_missing_migration_is_applied_normally(self):
        """Happy path: column absent, migration applies cleanly."""
        with tempfile.TemporaryDirectory() as d:
            db_path = pathlib.Path(d) / "db.sqlite"
            _make_db(db_path, column_present=False)
            stub = _StubActual(d, {TREND_FILE: TREND_SQL})
            Actual.run_migrations(stub, [TREND_FILE])
            conn = sqlite3.connect(db_path)
            cols = {r[1] for r in conn.execute("PRAGMA table_info(custom_reports)")}
            conn.close()
            self.assertIn("show_trend_lines", cols)
            self.assertIn(1780099200000, self._recorded(db_path))

    def test_already_recorded_migration_is_skipped(self):
        """A migration already in __migrations__ is never re-run."""
        with tempfile.TemporaryDirectory() as d:
            db_path = pathlib.Path(d) / "db.sqlite"
            _make_db(db_path, column_present=True, recorded_ids=[1780099200000])
            # data_file would raise if fetched; skipping means it is never called
            def _boom(_name):
                raise AssertionError("recorded migration should not be fetched")
            stub = _StubActual(d, {})
            stub.data_file = _boom
            Actual.run_migrations(stub, [TREND_FILE])

    def test_genuine_migration_error_still_raises(self):
        """A real failure (not an already-applied change) must not be swallowed."""
        broken = "ALTER TABLE table_that_does_not_exist ADD COLUMN z INTEGER;"
        with tempfile.TemporaryDirectory() as d:
            db_path = pathlib.Path(d) / "db.sqlite"
            _make_db(db_path, column_present=False)
            stub = _StubActual(d, {"migrations/1999999999999_broken.sql": broken})
            with self.assertRaises(sqlite3.OperationalError):
                Actual.run_migrations(stub, ["migrations/1999999999999_broken.sql"])
            # and it must NOT have been recorded as applied
            self.assertNotIn(1999999999999, self._recorded(db_path))


if __name__ == "__main__":
    unittest.main()
