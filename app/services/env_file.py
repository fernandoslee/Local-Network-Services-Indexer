"""Read and write the persistent .env configuration file."""

from pathlib import Path


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
    """Write a dict to a .env file, preserving existing keys not in values."""
    existing = read_env(path)
    existing.update(values)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{k}={v}" for k, v in existing.items()]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
