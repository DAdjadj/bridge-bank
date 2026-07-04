"""Version-tag based update detection via the Docker Hub API.

Works without the docker CLI or a mounted docker socket, so installs with a
broken or missing socket mount still learn about new releases instead of
being told they are up to date.
"""
import re
import logging
import requests

logger = logging.getLogger(__name__)

VERSION_RE = re.compile(r"\d{4}(?:\.\d+){2,3}")

def parse_version(version):
    """'2026.07.04.2' -> (2026, 7, 4, 2). None if not a release version tag."""
    if version and VERSION_RE.fullmatch(version):
        return tuple(int(p) for p in version.split("."))
    return None

def newest_remote_version(repo, timeout=5):
    """Newest release version tag on Docker Hub (e.g. '2026.07.04').

    Returns None if the tags cannot be fetched or none look like a version.
    """
    resp = requests.get(
        f"https://hub.docker.com/v2/repositories/{repo}/tags/?page_size=25",
        timeout=timeout,
    )
    resp.raise_for_status()
    best = None
    for tag in resp.json().get("results", []):
        parsed = parse_version(tag.get("name", ""))
        if parsed and (best is None or parsed > best[0]):
            best = (parsed, tag["name"])
    return best[1] if best else None

def update_available_by_version(current_version, repo):
    """Compare the running APP_VERSION against Docker Hub release tags.

    Returns (available, latest_tag). available is False when either side
    cannot be determined (e.g. APP_VERSION is 'dev').
    """
    try:
        latest = newest_remote_version(repo)
    except Exception as e:
        logger.warning("Could not fetch version tags for %s: %s", repo, e)
        return False, None
    current = parse_version(current_version)
    if not latest or not current:
        return False, latest
    return parse_version(latest) > current, latest
