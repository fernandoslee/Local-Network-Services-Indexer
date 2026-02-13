"""Unit tests for data models and service utilities."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from unraid_api.exceptions import UnraidAPIError, UnraidAuthenticationError

from app.models import ContainerInfo, VmInfo
from app.services.unraid import (
    UnraidService,
    _resolve_webui_url,
)


def _container(**overrides) -> ContainerInfo:
    defaults = dict(
        id="abc:def",
        name="test",
        state="RUNNING",
        image="img:latest",
        status="Up 2 hours",
        auto_start=True,
        web_ui_url=None,
        icon_url=None,
        network_mode="bridge",
        ports=[],
    )
    defaults.update(overrides)
    return ContainerInfo(**defaults)


# --- exit_code ---

class TestExitCode:
    def test_running_container_has_no_exit_code(self):
        c = _container(status="Up 2 hours")
        assert c.exit_code is None

    def test_exited_with_code_0(self):
        c = _container(state="EXITED", status="Exited (0) 3 hours ago")
        assert c.exit_code == 0

    def test_exited_with_code_143(self):
        c = _container(state="EXITED", status="Exited (143) 1 day ago")
        assert c.exit_code == 143

    def test_exited_with_code_137(self):
        c = _container(state="EXITED", status="Exited (137) 5 minutes ago")
        assert c.exit_code == 137

    def test_exited_with_code_1(self):
        c = _container(state="EXITED", status="Exited (1) 2 days ago")
        assert c.exit_code == 1

    def test_no_exit_code_in_status(self):
        c = _container(state="EXITED", status="Exited")
        assert c.exit_code is None


# --- exited_cleanly ---

class TestExitedCleanly:
    def test_code_0_is_clean(self):
        c = _container(state="EXITED", status="Exited (0) 3 hours ago")
        assert c.exited_cleanly is True

    def test_code_137_sigkill_is_clean(self):
        c = _container(state="EXITED", status="Exited (137) 5 minutes ago")
        assert c.exited_cleanly is True

    def test_code_143_sigterm_is_clean(self):
        c = _container(state="EXITED", status="Exited (143) 1 day ago")
        assert c.exited_cleanly is True

    def test_code_1_is_not_clean(self):
        c = _container(state="EXITED", status="Exited (1) 2 days ago")
        assert c.exited_cleanly is False

    def test_code_126_is_not_clean(self):
        c = _container(state="EXITED", status="Exited (126) 1 hour ago")
        assert c.exited_cleanly is False

    def test_no_code_is_clean(self):
        c = _container(state="EXITED", status="Exited")
        assert c.exited_cleanly is True


# --- state_lower ---

class TestStateLower:
    def test_running(self):
        assert _container(state="RUNNING").state_lower == "running"

    def test_paused(self):
        assert _container(state="PAUSED").state_lower == "paused"

    def test_exited_clean_becomes_stopped(self):
        c = _container(state="EXITED", status="Exited (0) 1 hour ago")
        assert c.state_lower == "stopped"

    def test_exited_crash_stays_exited(self):
        c = _container(state="EXITED", status="Exited (1) 1 hour ago")
        assert c.state_lower == "exited"

    def test_restarting(self):
        assert _container(state="RESTARTING").state_lower == "restarting"


# --- display_state ---

class TestDisplayState:
    def test_running(self):
        assert _container(state="RUNNING").display_state == "RUNNING"

    def test_exited_clean_shows_stopped(self):
        c = _container(state="EXITED", status="Exited (0) 1 hour ago")
        assert c.display_state == "STOPPED"

    def test_exited_crash_shows_failed(self):
        c = _container(state="EXITED", status="Exited (1) 1 hour ago")
        assert c.display_state == "FAILED"

    def test_exited_sigterm_shows_stopped(self):
        c = _container(state="EXITED", status="Exited (143) 1 day ago")
        assert c.display_state == "STOPPED"

    def test_paused(self):
        assert _container(state="PAUSED").display_state == "PAUSED"


# --- display_status ---

class TestDisplayStatus:
    def test_strips_healthy(self):
        c = _container(status="Up 2 hours (healthy)")
        assert c.display_status == "Up 2 hours"

    def test_strips_unhealthy(self):
        c = _container(status="Up 5 minutes (unhealthy)")
        assert c.display_status == "Up 5 minutes"

    def test_strips_exit_code(self):
        c = _container(state="EXITED", status="Exited (143) 3 months ago")
        assert c.display_status == "Exited 3 months ago"

    def test_plain_status_unchanged(self):
        c = _container(status="Up 2 hours")
        assert c.display_status == "Up 2 hours"


# --- is_running / is_restarting ---

class TestStateProperties:
    def test_is_running_true(self):
        assert _container(state="RUNNING").is_running is True

    def test_is_running_false(self):
        assert _container(state="EXITED").is_running is False

    def test_is_restarting_true(self):
        assert _container(state="RESTARTING").is_restarting is True

    def test_is_restarting_false(self):
        assert _container(state="RUNNING").is_restarting is False


# --- address ---

class TestAddress:
    def test_from_web_ui_url(self):
        c = _container(web_ui_url="http://192.168.1.100:8080/web")
        assert c.address == "192.168.1.100:8080"

    def test_from_web_ui_url_https(self):
        c = _container(web_ui_url="https://192.168.1.100/app")
        assert c.address == "192.168.1.100:443"

    def test_from_port_mapping(self):
        c = _container(
            web_ui_url=None,
            ports=[{"privatePort": 80, "publicPort": 8080, "ip": "0.0.0.0"}],
        )
        assert c.address == "0.0.0.0:8080"

    def test_no_address(self):
        c = _container(web_ui_url=None, ports=[])
        assert c.address is None


# --- port_list ---

class TestPortList:
    def test_web_ui_port(self):
        """When web_ui_url is set, show just its port."""
        c = _container(
            web_ui_url="http://192.168.50.177:8080/",
            ports=[
                {"privatePort": 80, "publicPort": 8080},
                {"privatePort": 443, "publicPort": 8443},
            ],
        )
        assert c.port_list == "8080"

    def test_single_port_no_webui(self):
        c = _container(ports=[{"privatePort": 80, "publicPort": 8080}])
        assert c.port_list == "8080"

    def test_multiple_ports_no_webui(self):
        c = _container(ports=[
            {"privatePort": 80, "publicPort": 8080},
            {"privatePort": 443, "publicPort": 8443},
        ])
        assert c.port_list == "8080, 8443"

    def test_private_only_no_webui(self):
        c = _container(ports=[{"privatePort": 80}])
        assert c.port_list == ""

    def test_empty(self):
        c = _container(ports=[])
        assert c.port_list == ""

    def test_truncates_after_three(self):
        c = _container(ports=[
            {"privatePort": i, "publicPort": i + 1000} for i in range(5)
        ])
        assert c.port_list.endswith("...")


# --- sort_key ---

class TestSortKey:
    def test_running_before_exited(self):
        r = _container(state="RUNNING", name="zzz")
        e = _container(state="EXITED", name="aaa")
        assert r.sort_key < e.sort_key

    def test_same_state_alphabetical(self):
        a = _container(name="alpha")
        b = _container(name="beta")
        assert a.sort_key < b.sort_key

    def test_case_insensitive(self):
        a = _container(name="Alpha")
        b = _container(name="alpha")
        assert a.sort_key == b.sort_key


# --- VmInfo ---

class TestVmInfo:
    def test_state_lower(self):
        vm = VmInfo(id="1", name="Test", state="RUNNING")
        assert vm.state_lower == "running"

    def test_is_running(self):
        assert VmInfo(id="1", name="Test", state="RUNNING").is_running is True
        assert VmInfo(id="1", name="Test", state="SHUTOFF").is_running is False

    def test_sort_key(self):
        r = VmInfo(id="1", name="zzz", state="RUNNING")
        s = VmInfo(id="2", name="aaa", state="SHUTOFF")
        assert r.sort_key < s.sort_key


# --- _resolve_webui_url ---

class TestResolveWebuiUrl:
    def test_empty_template(self):
        assert _resolve_webui_url("", "1.2.3.4", None, [], "bridge") is None

    def test_ip_replacement_bridge(self):
        url = _resolve_webui_url("http://[IP]:8080", "192.168.1.100", None, [], "bridge")
        assert url == "http://192.168.1.100:8080"

    def test_ip_replacement_macvlan(self):
        url = _resolve_webui_url("http://[IP]:8080", "192.168.1.100", "192.168.1.50", [], "br0")
        assert url == "http://192.168.1.50:8080"

    def test_macvlan_without_container_ip_uses_server(self):
        url = _resolve_webui_url("http://[IP]:80", "192.168.1.100", None, [], "br0")
        assert url == "http://192.168.1.100:80"

    def test_port_replacement(self):
        ports = [{"privatePort": 80, "publicPort": 8080}]
        url = _resolve_webui_url("http://[IP]:[PORT:80]", "1.2.3.4", None, ports, "bridge")
        assert url == "http://1.2.3.4:8080"

    def test_port_not_mapped_uses_private(self):
        url = _resolve_webui_url("http://[IP]:[PORT:80]", "1.2.3.4", None, [], "bridge")
        assert url == "http://1.2.3.4:80"

    def test_container_network_mode(self):
        url = _resolve_webui_url("http://[IP]:80", "192.168.1.100", None, [], "container:abc123")
        assert url == "http://192.168.1.100:80"

    def test_bridge_with_container_ip_uses_server_ip(self):
        """Bridge containers should use server IP, not internal Docker 172.17.x.x IP."""
        url = _resolve_webui_url("http://[IP]:5572", "192.168.1.100", "172.17.0.2", [], "bridge")
        assert url == "http://192.168.1.100:5572"

    def test_javascript_uri_rejected(self):
        """javascript: URIs should be rejected to prevent XSS."""
        url = _resolve_webui_url("javascript:alert(1)", "1.2.3.4", None, [], "bridge")
        assert url is None

    def test_data_uri_rejected(self):
        url = _resolve_webui_url("data:text/html,<script>alert(1)</script>", "1.2.3.4", None, [], "bridge")
        assert url is None

    def test_https_accepted(self):
        url = _resolve_webui_url("https://[IP]:443/app", "1.2.3.4", None, [], "bridge")
        assert url == "https://1.2.3.4:443/app"


# --- env_file security ---

class TestEnvFileSecurity:
    def test_newline_injection_stripped(self, tmp_path):
        from app.services.env_file import read_env, write_env

        env_path = tmp_path / ".env"
        write_env(env_path, {"KEY": "value\nINJECTED=evil"})
        result = read_env(env_path)
        assert "INJECTED" not in result
        assert result["KEY"] == "valueINJECTED=evil"  # newline stripped, no injection

    def test_carriage_return_stripped(self, tmp_path):
        from app.services.env_file import read_env, write_env

        env_path = tmp_path / ".env"
        write_env(env_path, {"KEY": "value\r\nINJECTED=evil"})
        result = read_env(env_path)
        assert "INJECTED" not in result

    def test_file_permissions(self, tmp_path):
        import stat
        from app.services.env_file import write_env

        env_path = tmp_path / ".env"
        write_env(env_path, {"KEY": "value"})
        mode = stat.S_IMODE(env_path.stat().st_mode)
        assert mode == 0o600


# --- _probe_container_control ---

class TestProbeContainerControl:
    @pytest.mark.asyncio
    async def test_generic_api_error_means_has_permission(self):
        """Non-permission API errors (e.g., 'not found') indicate the key has write access."""
        from unraid_api.exceptions import UnraidAPIError
        client = MagicMock()
        client.start_container = AsyncMock(side_effect=UnraidAPIError("container not found"))
        service = UnraidService(client)
        assert service._can_control_containers is None
        await service._probe_container_control()
        assert service._can_control_containers is True

    @pytest.mark.asyncio
    async def test_auth_error_means_no_permission(self):
        """UnraidAuthenticationError means the key lacks DOCKER:UPDATE_ANY."""
        from unraid_api.exceptions import UnraidAuthenticationError
        client = MagicMock()
        client.start_container = AsyncMock(side_effect=UnraidAuthenticationError("forbidden"))
        service = UnraidService(client)
        await service._probe_container_control()
        assert service._can_control_containers is False

    @pytest.mark.asyncio
    async def test_forbidden_message_means_no_permission(self):
        """API error containing 'forbidden' in message means no permission."""
        from unraid_api.exceptions import UnraidAPIError
        client = MagicMock()
        client.start_container = AsyncMock(
            side_effect=UnraidAPIError("Forbidden resource (path: ['startContainer'])")
        )
        service = UnraidService(client)
        await service._probe_container_control()
        assert service._can_control_containers is False

    @pytest.mark.asyncio
    async def test_unexpected_error_assumes_permission(self):
        """Unexpected errors (network, etc.) default to optimistic True."""
        client = MagicMock()
        client.start_container = AsyncMock(side_effect=ConnectionError("timeout"))
        service = UnraidService(client)
        await service._probe_container_control()
        assert service._can_control_containers is True

    def test_can_control_property_optimistic_before_probe(self):
        """Property returns True before probe runs."""
        client = MagicMock()
        service = UnraidService(client)
        assert service.can_control_containers is True

    @pytest.mark.asyncio
    async def test_can_control_property_after_probe_false(self):
        """Property returns False after probe detects no permission."""
        from unraid_api.exceptions import UnraidAuthenticationError
        client = MagicMock()
        client.start_container = AsyncMock(side_effect=UnraidAuthenticationError("forbidden"))
        service = UnraidService(client)
        await service._probe_container_control()
        assert service.can_control_containers is False


# --- check_permissions (connection) ---

class TestCheckPermissions:
    @pytest.mark.asyncio
    async def test_all_permissions_present(self):
        """No missing permissions when all queries succeed."""
        from app.services.connection import check_permissions
        client = MagicMock()
        client.query = AsyncMock(return_value={"vms": {"domains": []}, "info": {"os": {}}})
        client.start_container = AsyncMock(side_effect=UnraidAPIError("not found"))
        missing_req, missing_opt = await check_permissions(client)
        assert missing_req == []
        assert missing_opt == []

    @pytest.mark.asyncio
    async def test_missing_vms_permission(self):
        """VMS:READ_ANY detected as missing required permission."""
        from app.services.connection import check_permissions
        client = MagicMock()
        client.query = AsyncMock(side_effect=UnraidAuthenticationError("Forbidden resource"))
        client.start_container = AsyncMock(side_effect=UnraidAPIError("not found"))
        missing_req, missing_opt = await check_permissions(client)
        assert any(p[0] == "VMS:READ_ANY" for p in missing_req)

    @pytest.mark.asyncio
    async def test_missing_docker_write_is_optional(self):
        """DOCKER:UPDATE_ANY detected as missing optional permission."""
        from app.services.connection import check_permissions
        client = MagicMock()
        client.query = AsyncMock(return_value={"vms": {"domains": []}, "info": {"os": {}}})
        client.start_container = AsyncMock(
            side_effect=UnraidAuthenticationError("Forbidden resource")
        )
        missing_req, missing_opt = await check_permissions(client)
        assert missing_req == []
        assert any(p[0] == "DOCKER:UPDATE_ANY" for p in missing_opt)


# --- verify_password (auth_utils) ---

class TestVerifyPassword:
    def test_bcrypt_correct(self):
        import bcrypt as _bc
        from app.auth_utils import verify_password
        hashed = _bc.hashpw(b"mypassword", _bc.gensalt()).decode()
        assert verify_password("mypassword", hashed) is True

    def test_bcrypt_wrong(self):
        import bcrypt as _bc
        from app.auth_utils import verify_password
        hashed = _bc.hashpw(b"mypassword", _bc.gensalt()).decode()
        assert verify_password("wrongpassword", hashed) is False

    def test_plaintext_correct(self):
        from app.auth_utils import verify_password
        assert verify_password("secret", "secret") is True

    def test_plaintext_wrong(self):
        from app.auth_utils import verify_password
        assert verify_password("wrong", "secret") is False

    def test_bcrypt_2a_prefix(self):
        """Handles $2a$ prefix (older bcrypt versions)."""
        import bcrypt as _bc
        from app.auth_utils import verify_password
        hashed = _bc.hashpw(b"test", _bc.gensalt()).decode()
        # Replace $2b$ with $2a$ — bcrypt accepts both
        hashed_2a = hashed.replace("$2b$", "$2a$", 1)
        assert verify_password("test", hashed_2a) is True


# --- validate_host (connection) ---

class TestValidateHost:
    def test_valid_hostname(self):
        from app.services.connection import validate_host
        assert validate_host("tower.local") is None

    def test_valid_ip(self):
        from app.services.connection import validate_host
        assert validate_host("192.168.1.100") is None

    def test_valid_ip_with_port(self):
        from app.services.connection import validate_host
        assert validate_host("192.168.1.100:8443") is None

    def test_empty(self):
        from app.services.connection import validate_host
        assert validate_host("") is not None
        assert "required" in validate_host("").lower()

    def test_whitespace_only(self):
        from app.services.connection import validate_host
        assert validate_host("   ") is not None

    def test_too_long(self):
        from app.services.connection import validate_host
        assert validate_host("a" * 254) is not None
        assert "too long" in validate_host("a" * 254).lower()

    def test_scheme_rejected(self):
        from app.services.connection import validate_host
        assert validate_host("http://tower.local") is not None

    def test_path_rejected(self):
        from app.services.connection import validate_host
        assert validate_host("tower.local/graphql") is not None

    def test_whitespace_stripped(self):
        from app.services.connection import validate_host
        assert validate_host("  tower.local  ") is None


# --- _is_permission_error (connection) ---

class TestIsPermissionError:
    def test_authentication_error(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(UnraidAuthenticationError("test")) is True

    def test_forbidden_in_message(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(UnraidAPIError("Forbidden resource")) is True

    def test_unauthorized_in_message(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(UnraidAPIError("Unauthorized access")) is True

    def test_permission_in_message(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(UnraidAPIError("Permission denied")) is True

    def test_generic_error_not_permission(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(UnraidAPIError("container not found")) is False

    def test_non_api_error(self):
        from app.services.connection import _is_permission_error
        assert _is_permission_error(ConnectionError("timeout")) is False


# --- _mask_key (settings) ---

class TestMaskKey:
    def test_normal_key(self):
        from app.routers.settings import _mask_key
        masked = _mask_key("abcdefgh12345678")
        assert masked.endswith("5678")
        assert "\u2022" in masked

    def test_short_key(self):
        from app.routers.settings import _mask_key
        assert _mask_key("abc") == "abc"

    def test_exactly_four(self):
        from app.routers.settings import _mask_key
        assert _mask_key("abcd") == "abcd"

    def test_five_chars(self):
        from app.routers.settings import _mask_key
        masked = _mask_key("abcde")
        assert masked.endswith("bcde")
        assert len(masked) == 12  # 8 bullets + 4 chars


# --- env_file preserves existing keys ---

class TestEnvFilePreserve:
    def test_preserves_existing_keys(self, tmp_path):
        from app.services.env_file import read_env, write_env
        env_path = tmp_path / ".env"
        write_env(env_path, {"KEY1": "value1", "KEY2": "value2"})
        write_env(env_path, {"KEY2": "updated"})
        result = read_env(env_path)
        assert result["KEY1"] == "value1"
        assert result["KEY2"] == "updated"

    def test_read_empty_file(self, tmp_path):
        from app.services.env_file import read_env
        env_path = tmp_path / ".env"
        env_path.write_text("")
        assert read_env(env_path) == {}

    def test_read_nonexistent_file(self, tmp_path):
        from app.services.env_file import read_env
        assert read_env(tmp_path / "missing.env") == {}

    def test_skips_comments(self, tmp_path):
        from app.services.env_file import read_env
        env_path = tmp_path / ".env"
        env_path.write_text("# comment\nKEY=value\n")
        result = read_env(env_path)
        assert result == {"KEY": "value"}


# --- DockerService._parse_log_lines ---

class TestParseLogLines:
    def test_standard_docker_timestamp(self):
        from app.services.docker import DockerService
        raw = "2024-01-15T10:30:45.123456789Z Container started successfully"
        lines = DockerService._parse_log_lines(raw)
        assert len(lines) == 1
        assert lines[0]["timestamp"] == "2024-01-15 10:30:45"
        assert lines[0]["message"] == "Container started successfully"

    def test_no_timestamp(self):
        from app.services.docker import DockerService
        raw = "Just a plain log line"
        lines = DockerService._parse_log_lines(raw)
        assert len(lines) == 1
        assert lines[0]["timestamp"] == ""
        assert lines[0]["message"] == "Just a plain log line"

    def test_empty_lines_skipped(self):
        from app.services.docker import DockerService
        raw = "line1\n\n\nline2"
        lines = DockerService._parse_log_lines(raw)
        assert len(lines) == 2

    def test_multiple_lines(self):
        from app.services.docker import DockerService
        raw = (
            "2024-01-15T10:30:45.123Z First line\n"
            "2024-01-15T10:30:46.456Z Second line\n"
        )
        lines = DockerService._parse_log_lines(raw)
        assert len(lines) == 2
        assert lines[0]["message"] == "First line"
        assert lines[1]["message"] == "Second line"
