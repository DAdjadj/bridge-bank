"""Migration SQL from the Actual server stays inside the budget copy.

Bridge Bank runs the migration files the Actual server serves on its local
copy of the budget. app.sql_confine refuses ATTACH, DETACH and VACUUM INTO on
that connection, so a hostile migration can't read or rewrite instance.db
(the Enable Banking key, the account bindings) or write files elsewhere,
while Actual's real migrations run as before. Standard library only: this
runs without actualpy (test_migration_idempotency covers the patched loader).
"""
import pathlib
import sqlite3
import tempfile
import unittest

from app.sql_confine import confine_to_main_database


def _budget(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE __migrations__ (id INTEGER PRIMARY KEY);")
    conn.execute("CREATE TABLE custom_reports (id TEXT PRIMARY KEY, name TEXT);")
    conn.commit()
    conn.close()


def _instance_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);")
    conn.execute("INSERT INTO settings VALUES ('eb_pem_content', 'real key');")
    conn.commit()
    conn.close()


class MigrationAttachGuardTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        self.budget = self.dir / "db.sqlite"
        self.instance = self.dir / "instance.db"
        _budget(self.budget)
        _instance_db(self.instance)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, sql):
        conn = sqlite3.connect(self.budget)
        try:
            confine_to_main_database(conn)
            conn.executescript(sql)
            conn.commit()
        finally:
            conn.close()

    def _stored_key(self):
        conn = sqlite3.connect(self.instance)
        try:
            return conn.execute("SELECT value FROM settings WHERE key = 'eb_pem_content'").fetchone()[0]
        finally:
            conn.close()

    def test_normal_actual_migration_runs(self):
        self._run(
            "BEGIN TRANSACTION;\n"
            "ALTER TABLE custom_reports ADD COLUMN show_trend_lines INTEGER DEFAULT 0;\n"
            "CREATE TABLE payee_locations (id TEXT PRIMARY KEY, payee_id TEXT);\n"
            "CREATE INDEX payee_locations_payee ON payee_locations (payee_id);\n"
            "INSERT INTO custom_reports (id, name) VALUES ('r1', 'Spending');\n"
            "COMMIT;\n"
        )
        conn = sqlite3.connect(self.budget)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(custom_reports)")}
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        conn.close()
        self.assertIn("show_trend_lines", cols)
        self.assertIn("payee_locations", tables)

    def test_attach_is_refused_and_instance_db_untouched(self):
        with self.assertRaises(sqlite3.DatabaseError):
            self._run(
                f"ATTACH DATABASE '{self.instance}' AS bb;\n"
                "UPDATE bb.settings SET value = 'swapped';\n"
            )
        self.assertEqual(self._stored_key(), "real key")

    def test_attach_cannot_create_a_new_file(self):
        target = self.dir / "elsewhere" / "new.db"
        target.parent.mkdir()
        with self.assertRaises(sqlite3.DatabaseError):
            self._run(f"ATTACH DATABASE '{target}' AS x;\nCREATE TABLE x.t (a);\n")
        self.assertFalse(target.exists())

    def test_vacuum_into_is_refused(self):
        target = self.dir / "copy.db"
        with self.assertRaises(sqlite3.DatabaseError):
            self._run(f"VACUUM INTO '{target}';")
        self.assertFalse(target.exists())

    def test_detach_is_refused(self):
        with self.assertRaises(sqlite3.DatabaseError):
            self._run("DETACH DATABASE main;")


if __name__ == "__main__":
    unittest.main()
