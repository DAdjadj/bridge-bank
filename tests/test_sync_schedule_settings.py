"""A sync time or frequency that can't be read never stops the scheduler.

The Status page and the setup page both save the schedule. A value like
"25:00" or "weekly" used to be saved as is, and the scheduler then failed on
start and stopped syncing without saying why. app.config now checks values
before they're saved and falls back to 06:00 every 24 hours when what's
stored (from an older version, or an environment variable) can't be read.
Standard library only.
"""
import unittest
from unittest.mock import patch

from app import config


class SyncTimeTest(unittest.TestCase):
    def test_good_times(self):
        for value, expected in (("06:00", "06:00"), ("6:30", "06:30"), (" 23:59 ", "23:59"), ("00:00", "00:00")):
            with self.subTest(value):
                self.assertEqual(config.parse_sync_time(value), expected)

    def test_bad_times(self):
        for value in ("", None, "24:00", "12:60", "6", "06:5", "06:00:00", "6pm", "ab:cd", "-1:00", "06-00"):
            with self.subTest(value):
                self.assertIsNone(config.parse_sync_time(value))

    def test_reading_falls_back(self):
        with patch.object(config, "SYNC_TIME", "25:99"):
            self.assertEqual(config.sync_time(), "06:00")
        with patch.object(config, "SYNC_TIME", ""):
            self.assertEqual(config.sync_time(), "06:00")
        with patch.object(config, "SYNC_TIME", "7:15"):
            self.assertEqual(config.sync_time(), "07:15")


class SyncFrequencyTest(unittest.TestCase):
    def test_choices(self):
        for value, expected in (("0", 0), ("6", 6), ("12", 12), ("24", 24), (" 8 ", 8), (4, 4)):
            with self.subTest(value):
                self.assertEqual(config.parse_sync_frequency(value), expected)

    def test_bad_frequencies(self):
        for value in ("", None, "weekly", "-6", "5", "25", "48", "6.5", "1e1"):
            with self.subTest(value):
                self.assertIsNone(config.parse_sync_frequency(value))

    def test_reading_falls_back(self):
        with patch.object(config, "SYNC_FREQUENCY", "weekly"):
            self.assertEqual(config.sync_frequency(), 24)
        with patch.object(config, "SYNC_FREQUENCY", "0"):
            self.assertEqual(config.sync_frequency(), 0)
        with patch.object(config, "SYNC_FREQUENCY", "12"):
            self.assertEqual(config.sync_frequency(), 12)


if __name__ == "__main__":
    unittest.main()
