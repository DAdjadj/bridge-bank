"""Tests for the one-time Watchtower scope repair of existing compose files.

Pre-2026.10.12 installs run an unscoped Watchtower, which current Watchtower
versions delete (or which deletes the customer's own) when a second unscoped
Watchtower runs on the same host. The repair edits the customer's file, so it
must only add the scope lines, keep everything else byte for byte, and leave
any file it does not recognise alone.
"""
import unittest

from app.compose_scope import add_watchtower_scope

NAMES = ("bridge-bank", "bridge-bank-watchtower", "bridge-bank")

OLD_TEMPLATE = """services:
  bridge-bank:
    image: daalves/bridge-bank:latest
    container_name: bridge-bank
    restart: unless-stopped
    volumes:
      - ./data:/data
      - /var/run/docker.sock:/var/run/docker.sock
      - .:/compose:ro
    ports:
      - "3002:3000"
    extra_hosts:
      - "plex-server:host-gateway"

  watchtower:
    image: nickfedor/watchtower
    container_name: bridge-bank-watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --cleanup --interval 86400 --http-api-update --http-api-periodic-polls bridge-bank
    dns:
      - 1.1.1.1
      - 8.8.8.8
    environment:
      - WATCHTOWER_LOG_LEVEL=warn
      - WATCHTOWER_HTTP_API_TOKEN=bridge-bank-update
"""

NEW_TEMPLATE = """services:
  bridge-bank:
    image: daalves/bridge-bank:latest
    container_name: bridge-bank
    labels:
      - com.centurylinklabs.watchtower.scope=bridge-bank
    restart: unless-stopped
    volumes:
      - ./data:/data
      - /var/run/docker.sock:/var/run/docker.sock
      - .:/compose:ro
    ports:
      - "3002:3000"
    extra_hosts:
      - "plex-server:host-gateway"

  watchtower:
    image: nickfedor/watchtower
    container_name: bridge-bank-watchtower
    labels:
      - com.centurylinklabs.watchtower.scope=bridge-bank
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --cleanup --interval 86400 --http-api-update --http-api-periodic-polls bridge-bank
    dns:
      - 1.1.1.1
      - 8.8.8.8
    environment:
      - WATCHTOWER_LOG_LEVEL=warn
      - WATCHTOWER_HTTP_API_TOKEN=bridge-bank-update
      - WATCHTOWER_SCOPE=bridge-bank
"""


class AddWatchtowerScopeTest(unittest.TestCase):
    def test_old_template_becomes_the_new_one(self):
        self.assertEqual(add_watchtower_scope(OLD_TEMPLATE, *NAMES), NEW_TEMPLATE)

    def test_already_scoped_file_is_left_alone(self):
        self.assertIsNone(add_watchtower_scope(NEW_TEMPLATE, *NAMES))

    def test_customer_edits_are_kept(self):
        edited = OLD_TEMPLATE.replace('"3002:3000"', '"8080:3000"').replace(
            "    restart: unless-stopped\n    volumes:\n      - ./data",
            "    restart: always  # mine\n    volumes:\n      - /srv/bb:/data", 1)
        out = add_watchtower_scope(edited, *NAMES)
        self.assertIn('"8080:3000"', out)
        self.assertIn("restart: always  # mine", out)
        self.assertIn("- /srv/bb:/data", out)
        self.assertEqual(out.count("watchtower.scope=bridge-bank"), 2)

    def test_windows_line_endings_are_kept(self):
        out = add_watchtower_scope(OLD_TEMPLATE.replace("\n", "\r\n"), *NAMES)
        self.assertEqual(out, NEW_TEMPLATE.replace("\n", "\r\n"))

    def test_existing_label_list_gets_one_more_item(self):
        text = OLD_TEMPLATE.replace(
            "    container_name: bridge-bank\n",
            "    container_name: bridge-bank\n    labels:\n      - \"traefik.enable=true\"\n", 1)
        out = add_watchtower_scope(text, *NAMES)
        self.assertIn('    labels:\n      - "traefik.enable=true"\n'
                      "      - com.centurylinklabs.watchtower.scope=bridge-bank\n", out)
        self.assertEqual(out.count("    labels:\n"), 2)

    def test_mapping_style_labels_are_left_alone(self):
        text = OLD_TEMPLATE.replace(
            "    container_name: bridge-bank\n",
            "    container_name: bridge-bank\n    labels:\n      traefik.enable: \"true\"\n", 1)
        self.assertIsNone(add_watchtower_scope(text, *NAMES))

    def test_mapping_style_environment_is_left_alone(self):
        text = OLD_TEMPLATE.replace(
            "      - WATCHTOWER_LOG_LEVEL=warn\n      - WATCHTOWER_HTTP_API_TOKEN=bridge-bank-update\n",
            "      WATCHTOWER_LOG_LEVEL: warn\n      WATCHTOWER_HTTP_API_TOKEN: bridge-bank-update\n")
        self.assertIsNone(add_watchtower_scope(text, *NAMES))

    def test_file_without_our_watchtower_is_left_alone(self):
        text = OLD_TEMPLATE.split("\n  watchtower:")[0] + "\n"
        self.assertIsNone(add_watchtower_scope(text, *NAMES))

    def test_renamed_containers_are_left_alone(self):
        text = OLD_TEMPLATE.replace("container_name: bridge-bank-watchtower", "container_name: wt")
        self.assertIsNone(add_watchtower_scope(text, *NAMES))

    def test_top_level_sections_after_services_are_untouched(self):
        text = OLD_TEMPLATE + "\nnetworks:\n  media:\n    external: true\n"
        out = add_watchtower_scope(text, *NAMES)
        self.assertTrue(out.endswith("      - WATCHTOWER_SCOPE=bridge-bank\n\nnetworks:\n  media:\n    external: true\n"))


if __name__ == "__main__":
    unittest.main()
