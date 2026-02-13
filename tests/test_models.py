"""Unit tests for data models and service utilities."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from unraid_api.exceptions import UnraidAPIError, UnraidAuthenticationError

from app.services.unraid import (
    ContainerInfo,
    PluginInfo,
    UnraidService,
    VmInfo,
    _humanize_plugin_name,
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


# --- _humanize_plugin_name ---

class TestHumanizePluginName:
    def test_unraid_prefix(self):
        assert _humanize_plugin_name("unraid.community-applications") == "Community Applications"

    def test_no_prefix(self):
        assert _humanize_plugin_name("my-plugin") == "My Plugin"

    def test_underscores(self):
        assert _humanize_plugin_name("my_cool_plugin") == "My Cool Plugin"

    def test_dotted_name(self):
        assert _humanize_plugin_name("unraid.fix-common-problems") == "Fix Common Problems"


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


# --- _check_permissions (setup) ---

class TestCheckPermissions:
    @pytest.mark.asyncio
    async def test_all_permissions_present(self):
        """No missing permissions when all queries succeed."""
        from app.routers.setup import _check_permissions
        client = MagicMock()
        client.query = AsyncMock(return_value={"vms": {"domains": []}, "info": {"os": {}}})
        client.start_container = AsyncMock(side_effect=UnraidAPIError("not found"))
        missing_req, missing_opt = await _check_permissions(client)
        assert missing_req == []
        assert missing_opt == []

    @pytest.mark.asyncio
    async def test_missing_vms_permission(self):
        """VMS:READ_ANY detected as missing required permission."""
        from app.routers.setup import _check_permissions
        client = MagicMock()
        client.query = AsyncMock(side_effect=UnraidAuthenticationError("Forbidden resource"))
        client.start_container = AsyncMock(side_effect=UnraidAPIError("not found"))
        missing_req, missing_opt = await _check_permissions(client)
        assert any(p[0] == "VMS:READ_ANY" for p in missing_req)

    @pytest.mark.asyncio
    async def test_missing_docker_write_is_optional(self):
        """DOCKER:UPDATE_ANY detected as missing optional permission."""
        from app.routers.setup import _check_permissions
        client = MagicMock()
        client.query = AsyncMock(return_value={"vms": {"domains": []}, "info": {"os": {}}})
        client.start_container = AsyncMock(
            side_effect=UnraidAuthenticationError("Forbidden resource")
        )
        missing_req, missing_opt = await _check_permissions(client)
        assert missing_req == []
        assert any(p[0] == "DOCKER:UPDATE_ANY" for p in missing_opt)
