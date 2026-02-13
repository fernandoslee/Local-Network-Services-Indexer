"""Read and write the persistent .env configuration file."""

import os
import tempfile
from pathlib import Path


def _sanitize_value(value: str) -> str:
    """Strip newlines and carriage returns to prevent .env injection."""
    return value.replace("\n", "").replace("\r", "")


def read_env(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict."""
    result = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def write_env(path: Path, values: dict[str, str]) -> None:
    """Write a dict to a .env file, preserving existing keys not in values.

    Uses atomic write (write to temp file, then rename) and sanitizes
    values to prevent .env injection via newlines.
    """
    existing = read_env(path)
    existing.update(values)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{_sanitize_value(k)}={_sanitize_value(v)}" for k, v in existing.items()]
    content = "\n".join(lines) + "\n"

    # Atomic write: write to temp file, set permissions, then rename
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    os.close(fd)
    try:
        tmp = Path(tmp_path)
        tmp.write_text(content)
        tmp.chmod(0o600)
        tmp.rename(path)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
