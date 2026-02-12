"""Unit tests for app.config and helper functions in app.main."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config import Settings
from app.main import format_bytes, format_uptime
from app.services.env_file import read_env, write_env


def _settings(**kwargs) -> Settings:
    """Create a Settings instance that ignores the real .env file."""
    kwargs.setdefault("data_dir", "/tmp/test")
    return Settings(_env_file="/dev/null", **kwargs)


# --- Settings ---

class TestSettings:
    def test_defaults(self):
        s = _settings()
        assert s.unraid_host == ""
        assert s.unraid_api_key == ""
        assert s.unraid_verify_ssl is False
        assert s.poll_interval_seconds == 30
        assert s.cache_ttl_seconds == 10

    def test_is_configured_false_when_empty(self):
        s = _settings()
        assert s.is_configured is False

    def test_is_configured_true(self):
        s = _settings(unraid_host="tower", unraid_api_key="key123")
        assert s.is_configured is True

    def test_is_configured_false_missing_key(self):
        s = _settings(unraid_host="tower")
        assert s.is_configured is False

    def test_auth_defaults(self):
        s = _settings()
        assert s.auth_enabled is False
        assert s.auth_username == "admin"
        assert s.auth_password == ""

    def test_is_auth_configured_false_by_default(self):
        s = _settings()
        assert s.is_auth_configured is False

    def test_is_auth_configured_true(self):
        s = _settings(auth_enabled=True, auth_username="admin",
                      auth_password="secret")
        assert s.is_auth_configured is True

    def test_is_auth_configured_false_no_password(self):
        s = _settings(auth_enabled=True, auth_username="admin",
                      auth_password="")
        assert s.is_auth_configured is False


# --- format_bytes ---

class TestFormatBytes:
    def test_none(self):
        assert format_bytes(None) == "N/A"

    def test_bytes(self):
        assert format_bytes(500) == "500.0 B"

    def test_kilobytes(self):
        assert format_bytes(1536) == "1.5 KB"

    def test_megabytes(self):
        assert format_bytes(10 * 1024 * 1024) == "10.0 MB"

    def test_gigabytes(self):
        assert format_bytes(32 * 1024 ** 3) == "32.0 GB"

    def test_terabytes(self):
        assert format_bytes(2 * 1024 ** 4) == "2.0 TB"


# --- format_uptime ---

class TestFormatUptime:
    def test_none(self):
        assert format_uptime(None) == "N/A"

    def test_hours_and_minutes(self):
        now = datetime.now()
        boot = now - timedelta(hours=2, minutes=15)
        result = format_uptime(boot)
        assert "2h" in result
        assert "15m" in result

    def test_days(self):
        now = datetime.now()
        boot = now - timedelta(days=5, hours=3, minutes=10)
        result = format_uptime(boot)
        assert "5d" in result
        assert "3h" in result


# --- env_file helpers ---

class TestEnvFile:
    def test_read_nonexistent(self, tmp_path):
        assert read_env(tmp_path / "missing.env") == {}

    def test_write_and_read(self, tmp_path):
        path = tmp_path / ".env"
        write_env(path, {"KEY1": "val1", "KEY2": "val2"})
        result = read_env(path)
        assert result["KEY1"] == "val1"
        assert result["KEY2"] == "val2"

    def test_preserves_existing_keys(self, tmp_path):
        path = tmp_path / ".env"
        write_env(path, {"A": "1", "B": "2"})
        write_env(path, {"B": "3", "C": "4"})
        result = read_env(path)
        assert result == {"A": "1", "B": "3", "C": "4"}

    def test_skips_comments_and_blanks(self, tmp_path):
        path = tmp_path / ".env"
        path.write_text("# comment\n\nKEY=value\n")
        result = read_env(path)
        assert result == {"KEY": "value"}

    def test_file_permissions(self, tmp_path):
        path = tmp_path / ".env"
        write_env(path, {"K": "V"})
        import stat
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
