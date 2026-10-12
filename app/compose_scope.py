"""One-time repair: give an existing install's bundled Watchtower its own scope.

Installs made before 2026.10.12 run an unscoped Watchtower. Current Watchtower
versions delete every other unscoped Watchtower on the same Docker host as an
"excess instance", so a customer who also runs their own Watchtower loses
either ours (and with it automatic updates) or theirs.

The customer's docker-compose.yml is mounted read-only at /compose, so the fix
is applied by a short-lived helper container: it backs the file up, rewrites
it in place (keeping owner and mode), validates it with `docker compose
config` and runs `docker compose up -d`. Only files that look like our own
template are touched; anything unexpected is left alone and logged.
"""
import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

SCOPE_LABEL = "com.centurylinklabs.watchtower.scope"
COMPOSE_PATH = "/compose/docker-compose.yml"
BACKUP_NAME = "docker-compose.yml.bak-watchtower-scope"
SETTING = "watchtower_scope_repair"

_KEY = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*(.*?)\s*$")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _blocks(lines):
    """Map each service's container_name to (start, end) line indexes."""
    try:
        top = next(i for i, l in enumerate(lines) if l.rstrip() == "services:")
    except StopIteration:
        return {}
    starts = []
    svc_indent = None
    for i in range(top + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ind = _indent(line)
        if ind == 0:
            break
        if svc_indent is None:
            svc_indent = ind
        if ind == svc_indent and _KEY.match(line) and not _KEY.match(line).group(3):
            starts.append(i)
    end_of_services = next(
        (i for i in range(top + 1, len(lines)) if lines[i].strip() and _indent(lines[i]) == 0
         and not lines[i].lstrip().startswith("#")),
        len(lines),
    )
    out = {}
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else end_of_services
        for i in range(s + 1, e):
            m = _KEY.match(lines[i])
            if m and m.group(2) == "container_name":
                name = m.group(3).strip("'\"")
                if name in out:
                    return {}
                out[name] = (s, e)
    return out


def _key_line(lines, start, end, key):
    """Index of `key:` directly under the service, or None."""
    key_indent = None
    for i in range(start + 1, end):
        if lines[i].strip() and not lines[i].lstrip().startswith("#"):
            key_indent = _indent(lines[i])
            break
    for i in range(start + 1, end):
        m = _KEY.match(lines[i])
        if m and len(m.group(1)) == key_indent and m.group(2) == key:
            return i, key_indent
    return None, key_indent


def _list_items(lines, key_idx, key_indent, end):
    """Indexes of the `- item` lines under a key, or None if it is not a list."""
    items = []
    for i in range(key_idx + 1, end):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _indent(line) <= key_indent:
            break
        if not line.lstrip().startswith("- "):
            return None
        items.append(i)
    return items or None


def _add_list_item(lines, start, end, key, item, inserts):
    """Queue `- item` under `key:` (creating the key). False if the shape is unexpected."""
    idx, key_indent = _key_line(lines, start, end, key)
    if key_indent is None:
        return False
    if idx is None:
        name_idx = next(i for i in range(start + 1, end)
                        if _KEY.match(lines[i]) and _KEY.match(lines[i]).group(2) == "container_name")
        pad = " " * key_indent
        inserts.append((name_idx + 1, [f"{pad}{key}:", f"{pad}  - {item}"]))
        return True
    if _KEY.match(lines[idx]).group(3):
        return False  # inline value, e.g. `labels: {}`
    items = _list_items(lines, idx, key_indent, end)
    if items is None:
        return False  # mapping form; leave it to the customer
    last = items[-1]
    inserts.append((last + 1, [" " * _indent(lines[last]) + f"- {item}"]))
    return True


def add_watchtower_scope(text, app_container, watchtower_container, scope):
    """Return the compose text with the scope added, or None to leave it alone."""
    if SCOPE_LABEL in text or "WATCHTOWER_SCOPE" in text:
        return None
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(newline)
    blocks = _blocks(lines)
    if app_container not in blocks or watchtower_container not in blocks:
        return None
    a_start, a_end = blocks[app_container]
    w_start, w_end = blocks[watchtower_container]
    w_body = newline.join(lines[w_start:w_end])
    if "watchtower" not in w_body or "WATCHTOWER_HTTP_API_TOKEN" not in w_body:
        return None
    inserts = []
    label = f"{SCOPE_LABEL}={scope}"
    ok = (
        _add_list_item(lines, a_start, a_end, "labels", label, inserts)
        and _add_list_item(lines, w_start, w_end, "labels", label, inserts)
        and _add_list_item(lines, w_start, w_end, "environment", f"WATCHTOWER_SCOPE={scope}", inserts)
    )
    if not ok:
        return None
    for at, new in sorted(inserts, key=lambda x: x[0], reverse=True):
        lines[at:at] = new
    return newline.join(lines)


_HELPER = r'''
set -e
cd "$DIR"
[ "$(sha256sum docker-compose.yml | cut -d' ' -f1)" = "$OLD_SHA" ] || { echo "compose file changed, skipping"; exit 3; }
python -c "import os,base64,sys;sys.stdout.buffer.write(base64.b64decode(os.environ['NEW_B64']))" > /tmp/new.yml
docker compose -p "$PROJECT" --project-directory "$DIR" -f /tmp/new.yml config -q
[ -e "$BACKUP" ] || cp -p docker-compose.yml "$BACKUP"
cat /tmp/new.yml > docker-compose.yml
sleep 2
docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" up -d
'''


def _docker(*args, timeout=10):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def repair(container_name, app_container, watchtower_container, scope, db, app_version):
    """Apply the scope to this install's compose file once. Returns a short status."""
    if not os.path.exists("/var/run/docker.sock") or not os.path.exists(COMPOSE_PATH):
        return "no-compose"
    with open(COMPOSE_PATH, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "unreadable"
    new = add_watchtower_scope(text, app_container, watchtower_container, scope)
    if new is None:
        return "not-needed-or-custom"
    if db.get_setting(SETTING) == app_version:
        return "already-tried"

    info = _docker("inspect", container_name)
    if info.returncode != 0:
        return "no-inspect"
    c = json.loads(info.stdout)[0]
    labels = c.get("Config", {}).get("Labels") or {}
    project = labels.get("com.docker.compose.project", "")
    config_files = labels.get("com.docker.compose.project.config_files", "")
    host_dir = next((m["Source"] for m in c.get("Mounts", []) if m.get("Destination") == "/compose"), "")
    if not project or not host_dir or config_files != f"{host_dir}/docker-compose.yml":
        # Started from another file, with overrides, or not by compose at all.
        return "not-our-compose"

    db.set_setting(SETTING, app_version)
    result = _docker(
        "run", "-d", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{host_dir}:{host_dir}",
        "-e", f"DIR={host_dir}",
        "-e", f"PROJECT={project}",
        "-e", f"BACKUP={BACKUP_NAME}",
        "-e", f"OLD_SHA={hashlib.sha256(raw).hexdigest()}",
        "-e", f"NEW_B64={base64.b64encode(new.encode()).decode()}",
        "--entrypoint", "sh",
        c.get("Image", ""), "-c", _HELPER,
        timeout=30,
    )
    if result.returncode != 0:
        logger.warning("Watchtower scope repair could not start: %s", result.stderr.strip())
        return "helper-failed"
    logger.info("Watchtower scope repair started for %s/docker-compose.yml", host_dir)
    return "started"


def schedule(delay, **kwargs):
    def _run():
        time.sleep(delay)
        try:
            logger.info("Watchtower scope repair: %s", repair(**kwargs))
        except Exception as e:
            logger.warning("Watchtower scope repair failed: %s", e)
    threading.Thread(target=_run, daemon=True).start()
