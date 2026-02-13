"""Integration tests for routes using FastAPI TestClient."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_PASSWORD, _make_cached_data


# --- Dashboard ---

@pytest.mark.asyncio
async def test_dashboard_returns_200(client):
    resp = await client.get("/?view=cards")
    assert resp.status_code == 200
    assert "Containers" in resp.text

@pytest.mark.asyncio
async def test_dashboard_compact_view(client):
    resp = await client.get("/?view=compact")
    assert resp.status_code == 200
    assert "compact-table" in resp.text or "Containers" in resp.text

@pytest.mark.asyncio
async def test_dashboard_redirects_when_unconfigured(client_unconfigured):
    resp = await client_unconfigured.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/setup" in resp.headers["location"]


# --- Setup Wizard ---

@pytest.mark.asyncio
async def test_setup_step1_shown_when_fresh(client_unconfigured):
    resp = await client_unconfigured.get("/setup")
    assert resp.status_code == 200
    assert "Create Your Account" in resp.text
    assert "/setup/credentials" in resp.text

@pytest.mark.asyncio
async def test_setup_step2_shown_after_auth(client_auth_only):
    resp = await client_auth_only.get("/setup")
    assert resp.status_code == 200
    assert "Connect to Unraid" in resp.text
    assert "Complete Setup" in resp.text

@pytest.mark.asyncio
async def test_setup_redirects_when_fully_configured(client_with_auth):
    # Must log in first to access /setup (session auth)
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.get("/setup", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"

@pytest.mark.asyncio
async def test_setup_credentials_passwords_must_match(client_unconfigured):
    resp = await client_unconfigured.post("/setup/credentials", data={
        "username": "admin",
        "password": "password123",
        "password_confirm": "different123",
    })
    assert resp.status_code == 200
    assert "do not match" in resp.text

@pytest.mark.asyncio
async def test_setup_credentials_password_min_length(client_unconfigured):
    resp = await client_unconfigured.post("/setup/credentials", data={
        "username": "admin",
        "password": "short",
        "password_confirm": "short",
    })
    assert resp.status_code == 200
    assert "at least 8" in resp.text

@pytest.mark.asyncio
async def test_setup_credentials_username_required(client_unconfigured):
    resp = await client_unconfigured.post("/setup/credentials", data={
        "username": "   ",
        "password": "password123",
        "password_confirm": "password123",
    })
    assert resp.status_code == 200
    assert "required" in resp.text.lower()


# --- Settings ---

@pytest.mark.asyncio
async def test_settings_page_returns_200(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "Server Connection" in resp.text
    assert "Authentication" in resp.text

@pytest.mark.asyncio
async def test_settings_shows_docker_access_section(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "Docker Access" in resp.text


# --- API Partials ---

@pytest.mark.asyncio
async def test_api_containers_cards(client):
    resp = await client.get("/api/containers?view=cards")
    assert resp.status_code == 200
    assert "test-container" in resp.text

@pytest.mark.asyncio
async def test_api_containers_compact(client):
    resp = await client.get("/api/containers?view=compact")
    assert resp.status_code == 200
    assert "test-container" in resp.text

@pytest.mark.asyncio
async def test_api_vms(client):
    resp = await client.get("/api/vms")
    assert resp.status_code == 200
    assert "TestVM" in resp.text

@pytest.mark.asyncio
async def test_api_system(client):
    resp = await client.get("/api/system")
    assert resp.status_code == 200
    assert "CPU" in resp.text

@pytest.mark.asyncio
async def test_api_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200

@pytest.mark.asyncio
async def test_api_not_connected(client_unconfigured):
    resp = await client_unconfigured.get("/api/containers")
    assert resp.status_code == 200
    assert "Not connected" in resp.text


# --- Container Logs ---

@pytest.mark.asyncio
async def test_container_logs_with_docker_socket(client, mock_docker_service):
    resp = await client.get("/api/containers/logs?id=abc123:def456")
    assert resp.status_code == 200
    assert "Container started" in resp.text
    assert "Listening on port 8080" in resp.text
    mock_docker_service.get_container_logs.assert_awaited_once_with("abc123:def456", tail=100)

@pytest.mark.asyncio
async def test_container_logs_without_docker_socket(client_unconfigured):
    resp = await client_unconfigured.get("/api/containers/logs?id=abc123:def456")
    assert resp.status_code == 200
    assert "Docker socket not available" in resp.text
    assert "docker-compose.yml" in resp.text


# --- Container Actions ---

@pytest.mark.asyncio
async def test_container_start(client, mock_service):
    resp = await client.post("/api/containers/start?id=abc123:def456&view=cards")
    assert resp.status_code == 200
    mock_service.start_container.assert_awaited_once_with("abc123:def456")

@pytest.mark.asyncio
async def test_container_stop(client, mock_service):
    resp = await client.post("/api/containers/stop?id=abc123:def456&view=cards")
    assert resp.status_code == 200
    mock_service.stop_container.assert_awaited_once_with("abc123:def456")

@pytest.mark.asyncio
async def test_container_restart(client, mock_service):
    resp = await client.post("/api/containers/restart?id=abc123:def456&view=cards")
    assert resp.status_code == 200
    mock_service.restart_container.assert_awaited_once_with("abc123:def456")


# --- VM Actions ---

@pytest.mark.asyncio
async def test_vm_start(client, mock_service):
    resp = await client.post("/api/vms/start?id=vm-1&view=cards")
    assert resp.status_code == 200
    mock_service.start_vm.assert_awaited_once_with("vm-1")

@pytest.mark.asyncio
async def test_vm_stop(client, mock_service):
    resp = await client.post("/api/vms/stop?id=vm-1&view=cards")
    assert resp.status_code == 200
    mock_service.stop_vm.assert_awaited_once_with("vm-1")

@pytest.mark.asyncio
async def test_vm_restart(client, mock_service):
    resp = await client.post("/api/vms/restart?id=vm-1&view=cards")
    assert resp.status_code == 200
    mock_service.restart_vm.assert_awaited_once_with("vm-1")

@pytest.mark.asyncio
async def test_vm_force_stop(client, mock_service):
    resp = await client.post("/api/vms/force-stop?id=vm-1&view=cards")
    assert resp.status_code == 200
    mock_service.force_stop_vm.assert_awaited_once_with("vm-1")

@pytest.mark.asyncio
async def test_vm_action_not_connected(client_unconfigured):
    resp = await client_unconfigured.post("/api/vms/start?id=vm-1")
    assert resp.status_code == 503
    assert "Not connected" in resp.text

@pytest.mark.asyncio
async def test_vm_start_error_still_returns_section(client, mock_service):
    """VM action errors are logged but section HTML is still returned."""
    mock_service.start_vm = AsyncMock(side_effect=Exception("API error"))
    resp = await client.post("/api/vms/start?id=vm-1&view=cards")
    assert resp.status_code == 200
    assert "TestVM" in resp.text


# --- VM Control Permission ---

@pytest.mark.asyncio
async def test_vms_cards_has_active_buttons_when_can_control(client):
    """Card view buttons should have hx-post when can_control=True (mock VM is RUNNING)."""
    resp = await client.get("/api/vms?view=cards")
    assert resp.status_code == 200
    assert 'hx-post="/api/vms/stop' in resp.text

@pytest.mark.asyncio
async def test_vms_compact_has_active_buttons_when_can_control(client):
    """Compact view buttons should have hx-post when can_control=True (mock VM is RUNNING)."""
    resp = await client.get("/api/vms?view=compact")
    assert resp.status_code == 200
    assert 'hx-post="/api/vms/stop' in resp.text

@pytest.mark.asyncio
async def test_vms_cards_has_disabled_buttons_when_no_control(mock_docker_service, configured_settings):
    """Card view buttons should be disabled when can_control_vms=False."""
    from unittest.mock import AsyncMock
    from app.main import app
    from tests.conftest import _patch_app_settings

    service = AsyncMock()
    service.get_all_data = AsyncMock(return_value=_make_cached_data(can_control_vms=False))
    service.can_control_vms = False

    patches = _patch_app_settings(app, configured_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = MagicMock()
        app.state.unraid_service = service
        app.state.docker_service = mock_docker_service
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/vms?view=cards")
            assert resp.status_code == 200
            assert "disabled" in resp.text
            assert "VMS:UPDATE_ANY permission required" in resp.text
            assert 'hx-post="/api/vms/stop' not in resp.text


# --- Session Auth ---

@pytest.mark.asyncio
async def test_auth_redirects_to_login(client_with_auth):
    resp = await client_with_auth.get("/?view=cards", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]

@pytest.mark.asyncio
async def test_login_page_renders(client_with_auth):
    resp = await client_with_auth.get("/login")
    assert resp.status_code == 200
    assert "Login" in resp.text
    assert "Sign In" in resp.text

@pytest.mark.asyncio
async def test_login_success_sets_session(client_with_auth):
    resp = await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    # Session cookie should be set
    assert "session" in resp.headers.get("set-cookie", "").lower()

@pytest.mark.asyncio
async def test_login_wrong_password(client_with_auth):
    resp = await client_with_auth.post("/login", data={
        "username": "admin", "password": "wrongpassword",
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text

@pytest.mark.asyncio
async def test_login_wrong_username(client_with_auth):
    resp = await client_with_auth.post("/login", data={
        "username": "hacker", "password": TEST_PASSWORD,
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text

@pytest.mark.asyncio
async def test_authenticated_access_with_session(client_with_auth):
    # Log in first
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    # Now access dashboard — session cookie persists in client
    resp = await client_with_auth.get("/?view=cards")
    assert resp.status_code == 200
    assert "Containers" in resp.text

@pytest.mark.asyncio
async def test_logout_clears_session(client_with_auth):
    # Log in
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    # Logout
    resp = await client_with_auth.post("/logout", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]
    # Dashboard should redirect to login now
    resp = await client_with_auth.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]

@pytest.mark.asyncio
async def test_auth_allows_static_files(client_with_auth):
    resp = await client_with_auth.get("/static/css/app.css")
    assert resp.status_code == 200

@pytest.mark.asyncio
async def test_login_redirects_when_already_authenticated(client_with_auth):
    # Log in
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    # Visit login page — should redirect to dashboard
    resp = await client_with_auth.get("/login", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


# --- Security Hardening ---

@pytest.mark.asyncio
async def test_setup_credentials_blocked_after_auth_configured(client_with_auth):
    """POST /setup/credentials should redirect if auth is already configured."""
    # Must log in first
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/setup/credentials", data={
        "username": "hacker",
        "password": "newpassword123",
        "password_confirm": "newpassword123",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"

@pytest.mark.asyncio
async def test_settings_auth_requires_current_password(client_with_auth):
    """POST /settings/auth should require correct current password."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    # Try without current password
    resp = await client_with_auth.post("/settings/auth", data={
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "",
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "Current password is incorrect" in resp.text

@pytest.mark.asyncio
async def test_settings_auth_wrong_current_password(client_with_auth):
    """POST /settings/auth should reject wrong current password."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/settings/auth", data={
        "current_password": "wrongpassword",
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "",
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "Current password is incorrect" in resp.text

@pytest.mark.asyncio
async def test_settings_auth_correct_current_password(client_with_auth):
    """POST /settings/auth should accept correct current password."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/settings/auth", data={
        "current_password": TEST_PASSWORD,
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "",
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "saved" in resp.text.lower()

@pytest.mark.asyncio
async def test_settings_auth_password_min_length(client_with_auth):
    """POST /settings/auth should enforce minimum password length."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/settings/auth", data={
        "current_password": TEST_PASSWORD,
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "short",
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "at least 8" in resp.text

@pytest.mark.asyncio
async def test_setup_credentials_password_max_length(client_unconfigured):
    """POST /setup/credentials should reject overly long passwords."""
    resp = await client_unconfigured.post("/setup/credentials", data={
        "username": "admin",
        "password": "a" * 200,
        "password_confirm": "a" * 200,
    })
    assert resp.status_code == 200
    assert "at most 128" in resp.text

@pytest.mark.asyncio
async def test_setup_credentials_username_max_length(client_unconfigured):
    """POST /setup/credentials should reject overly long usernames."""
    resp = await client_unconfigured.post("/setup/credentials", data={
        "username": "a" * 100,
        "password": "password123",
        "password_confirm": "password123",
    })
    assert resp.status_code == 200
    assert "too long" in resp.text.lower()


# --- Container Control Permission ---

@pytest.mark.asyncio
async def test_containers_cards_has_active_buttons_when_can_control(client):
    """Card view buttons should have hx-post when can_control=True."""
    resp = await client.get("/api/containers?view=cards")
    assert resp.status_code == 200
    assert 'hx-post="/api/containers/stop' in resp.text

@pytest.mark.asyncio
async def test_containers_compact_has_active_buttons_when_can_control(client):
    """Compact view buttons should have hx-post when can_control=True."""
    resp = await client.get("/api/containers?view=compact")
    assert resp.status_code == 200
    assert 'hx-post="/api/containers/stop' in resp.text

@pytest.mark.asyncio
async def test_containers_cards_has_disabled_buttons_when_no_control(mock_docker_service, configured_settings):
    """Card view buttons should be disabled when can_control=False."""
    from unittest.mock import AsyncMock
    from app.main import app
    from tests.conftest import _patch_app_settings

    service = AsyncMock()
    service.get_all_data = AsyncMock(return_value=_make_cached_data(can_control_containers=False))
    service.can_control_containers = False

    patches = _patch_app_settings(app, configured_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = MagicMock()
        app.state.unraid_service = service
        app.state.docker_service = mock_docker_service
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/containers?view=cards")
            assert resp.status_code == 200
            assert "disabled" in resp.text
            assert "DOCKER:UPDATE_ANY permission required" in resp.text
            assert 'hx-post="/api/containers/stop' not in resp.text

@pytest.mark.asyncio
async def test_containers_compact_has_disabled_buttons_when_no_control(mock_docker_service, configured_settings):
    """Compact view buttons should be disabled when can_control=False."""
    from unittest.mock import AsyncMock
    from app.main import app
    from tests.conftest import _patch_app_settings

    service = AsyncMock()
    service.get_all_data = AsyncMock(return_value=_make_cached_data(can_control_containers=False))
    service.can_control_containers = False

    patches = _patch_app_settings(app, configured_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = MagicMock()
        app.state.unraid_service = service
        app.state.docker_service = mock_docker_service
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/containers?view=compact")
            assert resp.status_code == 200
            assert "disabled" in resp.text
            assert "DOCKER:UPDATE_ANY permission required" in resp.text
            assert 'hx-post="/api/containers/stop' not in resp.text


# --- Rate Limiting ---

@pytest.mark.asyncio
async def test_login_rate_limiting(client_with_auth):
    """Exceeding rate limit returns error without checking credentials."""
    import time as _time
    from app.routers.auth import _login_attempts, _RATE_LIMIT_MAX
    # ASGITransport default client is ("127.0.0.1", 123)
    _login_attempts["127.0.0.1"] = [_time.monotonic()] * (_RATE_LIMIT_MAX + 1)
    try:
        resp = await client_with_auth.post("/login", data={
            "username": "admin", "password": TEST_PASSWORD,
        })
        assert resp.status_code == 200
        assert "Too many login attempts" in resp.text
    finally:
        _login_attempts.pop("127.0.0.1", None)


@pytest.mark.asyncio
async def test_login_max_password_length(client_with_auth):
    """Password exceeding MAX_PASSWORD_LENGTH rejected (bcrypt DoS prevention)."""
    resp = await client_with_auth.post("/login", data={
        "username": "admin", "password": "a" * 200,
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text


@pytest.mark.asyncio
async def test_login_when_auth_not_configured(client):
    """Login redirects to dashboard when auth is not configured."""
    resp = await client.post("/login", data={
        "username": "admin", "password": "whatever",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


# --- Middleware ---

@pytest.mark.asyncio
async def test_trailing_slash_normalization(client_with_auth):
    """Trailing slash should not bypass auth middleware."""
    resp = await client_with_auth.get("/settings/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]


@pytest.mark.asyncio
async def test_setup_accessible_during_step2(client_auth_only):
    """Setup paths should be accessible when auth is configured but Unraid is not."""
    resp = await client_auth_only.get("/setup")
    assert resp.status_code == 200
    assert "Connect to Unraid" in resp.text


# --- Settings Auth Edge Cases ---

@pytest.mark.asyncio
async def test_settings_auth_password_max_length(client_with_auth):
    """POST /settings/auth should enforce maximum password length."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/settings/auth", data={
        "current_password": TEST_PASSWORD,
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "a" * 200,
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "at most 128" in resp.text


@pytest.mark.asyncio
async def test_settings_auth_preserves_password_when_empty(client_with_auth):
    """Enabling auth with empty password preserves existing hash."""
    await client_with_auth.post("/login", data={
        "username": "admin", "password": TEST_PASSWORD,
    })
    resp = await client_with_auth.post("/settings/auth", data={
        "current_password": TEST_PASSWORD,
        "auth_enabled": "on",
        "auth_username": "admin",
        "auth_password": "",
        "session_max_age": "86400",
    })
    assert resp.status_code == 200
    assert "saved" in resp.text.lower()


# --- Setup Host Validation ---

@pytest.mark.asyncio
async def test_setup_host_validation_empty(client_auth_only):
    """Setup rejects whitespace-only host."""
    resp = await client_auth_only.post("/setup", data={
        "host": "   ",
        "api_key": "test-key",
    })
    assert resp.status_code == 200
    assert "required" in resp.text.lower()


@pytest.mark.asyncio
async def test_setup_host_validation_scheme(client_auth_only):
    """Setup rejects host with scheme (SSRF prevention)."""
    resp = await client_auth_only.post("/setup", data={
        "host": "http://tower.local",
        "api_key": "test-key",
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text or "hostname or IP" in resp.text


@pytest.mark.asyncio
async def test_setup_api_key_too_long(client_auth_only):
    """Setup rejects overly long API key."""
    resp = await client_auth_only.post("/setup", data={
        "host": "tower.local",
        "api_key": "a" * 300,
    })
    assert resp.status_code == 200
    assert "too long" in resp.text.lower()
