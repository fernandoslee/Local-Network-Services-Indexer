import os
from unittest.mock import AsyncMock, MagicMock, patch

import bcrypt
import pytest
from httpx import ASGITransport, AsyncClient

from app.models import (
    CachedData,
    ContainerInfo,
    SystemInfo,
    SystemMetrics,
    VmInfo,
)

# Prevent tests from reading real .env
os.environ.pop("UNRAID_HOST", None)
os.environ.pop("UNRAID_API_KEY", None)


def _patch_app_settings(app, settings):
    """Patch get_settings everywhere: module-level, routers, and auth middleware.

    The middleware stores get_settings_fn in user_middleware kwargs (used when
    building the middleware stack on first request) AND potentially on an already-
    built middleware_stack instance.  We patch both to be safe.
    """
    def getter():
        return settings
    getter.cache_clear = lambda: None  # stub for lru_cache compatibility

    # Patch user_middleware kwargs so newly built stacks use our getter
    for mw in app.user_middleware:
        if hasattr(mw, "kwargs") and "get_settings_fn" in mw.kwargs:
            mw.kwargs["get_settings_fn"] = getter

    # If middleware_stack was already built, patch the live instance
    from app.middleware import SessionAuthMiddleware
    obj = getattr(app, "middleware_stack", None)
    while obj is not None:
        if isinstance(obj, SessionAuthMiddleware):
            obj._get_settings = getter
            break
        obj = getattr(obj, "app", None)

    # Force rebuild of middleware stack on next request so our patched
    # user_middleware kwargs take effect
    app.middleware_stack = None

    return [
        patch("app.config.get_settings", getter),
        patch("app.routers.setup.get_settings", getter),
        patch("app.routers.settings.get_settings", getter),
        patch("app.routers.auth.get_settings", getter),
    ]


def _make_container(**overrides) -> ContainerInfo:
    defaults = dict(
        id="abc123:def456",
        name="test-container",
        state="RUNNING",
        image="test/image:latest",
        status="Up 2 hours",
        auto_start=True,
        web_ui_url="http://192.168.1.100:8080",
        icon_url="https://example.com/icon.png",
        network_mode="bridge",
        ports=[{"privatePort": 8080, "publicPort": 8080, "ip": "0.0.0.0", "type": "tcp"}],
    )
    defaults.update(overrides)
    return ContainerInfo(**defaults)


def _make_vm(**overrides) -> VmInfo:
    defaults = dict(id="vm-1", name="TestVM", state="RUNNING")
    defaults.update(overrides)
    return VmInfo(**defaults)


def _make_cached_data(**overrides) -> CachedData:
    defaults = dict(
        containers=[
            _make_container(),
            _make_container(id="xyz:789", name="stopped-container", state="EXITED",
                            status="Exited (0) 3 hours ago", web_ui_url=None),
        ],
        vms=[_make_vm()],
        plugins=[],
        system_info=SystemInfo(
            hostname="tower", cpu_brand="AMD Ryzen 9", cpu_cores=16,
            cpu_threads=32, lan_ip="192.168.1.100",
        ),
        system_metrics=SystemMetrics(cpu_percent=25.0, memory_percent=45.2),
        last_fetched=1000.0,
        error=None,
    )
    defaults.update(overrides)
    return CachedData(**defaults)


@pytest.fixture
def mock_service():
    """Create a mock UnraidService that returns test data."""
    service = AsyncMock()
    service.get_all_data = AsyncMock(return_value=_make_cached_data())
    service.start_container = AsyncMock(return_value={})
    service.stop_container = AsyncMock(return_value={})
    service.restart_container = AsyncMock(return_value={})
    service.can_control_containers = True
    service.start_vm = AsyncMock(return_value={})
    service.stop_vm = AsyncMock(return_value={})
    service.restart_vm = AsyncMock(return_value={})
    service.force_stop_vm = AsyncMock(return_value={})
    service.can_control_vms = True
    return service


@pytest.fixture
def mock_docker_service():
    """Create a mock DockerService that returns sample log data."""
    service = AsyncMock()
    service.get_container_logs = AsyncMock(return_value=[
        {"timestamp": "2024-01-15 10:30:45", "message": "Container started"},
        {"timestamp": "2024-01-15 10:30:46", "message": "Listening on port 8080"},
    ])
    return service


@pytest.fixture
def unconfigured_settings():
    """Settings with no Unraid connection configured."""
    from app.config import Settings
    return Settings(
        _env_file="/dev/null",
        unraid_host="",
        unraid_api_key="",
        data_dir="/tmp/test-data",
    )


@pytest.fixture
def configured_settings():
    """Settings with Unraid connection configured."""
    from app.config import Settings
    return Settings(
        _env_file="/dev/null",
        unraid_host="tower.local",
        unraid_api_key="test-api-key-12345",
        data_dir="/tmp/test-data",
    )


TEST_PASSWORD = "secret123"
TEST_PASSWORD_HASH = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt()).decode()


@pytest.fixture
def auth_settings():
    """Settings with auth enabled."""
    from app.config import Settings
    return Settings(
        _env_file="/dev/null",
        unraid_host="tower.local",
        unraid_api_key="test-api-key-12345",
        auth_enabled=True,
        auth_username="admin",
        auth_password=TEST_PASSWORD_HASH,
        session_secret_key="test-session-secret-key-for-testing",
        data_dir="/tmp/test-data",
    )


@pytest.fixture
def auth_only_settings():
    """Settings with auth configured but no Unraid connection."""
    from app.config import Settings
    return Settings(
        _env_file="/dev/null",
        unraid_host="",
        unraid_api_key="",
        auth_enabled=True,
        auth_username="admin",
        auth_password=TEST_PASSWORD_HASH,
        session_secret_key="test-session-secret-key-for-testing",
        data_dir="/tmp/test-data",
    )


@pytest.fixture
def app_auth_only(auth_only_settings):
    """App with auth configured but Unraid unconfigured (setup step 2)."""
    from app.main import app
    patches = _patch_app_settings(app, auth_only_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = None
        app.state.unraid_service = None
        app.state.docker_service = None
        yield app


@pytest.fixture
async def client_auth_only(app_auth_only):
    """Async HTTP client for auth-only configured app."""
    async with AsyncClient(
        transport=ASGITransport(app=app_auth_only),
        base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def app_with_service(mock_service, mock_docker_service, configured_settings):
    """Create a test app with a mocked UnraidService."""
    from app.main import app
    patches = _patch_app_settings(app, configured_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = MagicMock()
        app.state.unraid_service = mock_service
        app.state.docker_service = mock_docker_service
        yield app


@pytest.fixture
def app_unconfigured(unconfigured_settings):
    """Create a test app with no UnraidService (unconfigured)."""
    from app.main import app
    patches = _patch_app_settings(app, unconfigured_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = None
        app.state.unraid_service = None
        app.state.docker_service = None
        yield app


@pytest.fixture
def app_with_auth(mock_service, mock_docker_service, auth_settings):
    """Create a test app with auth enabled."""
    from app.main import app
    patches = _patch_app_settings(app, auth_settings)
    with patches[0], patches[1], patches[2], patches[3]:
        app.state.unraid_client = MagicMock()
        app.state.unraid_service = mock_service
        app.state.docker_service = mock_docker_service
        yield app


@pytest.fixture
async def client(app_with_service):
    """Async HTTP client for testing with a configured app."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_service),
        base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
async def client_unconfigured(app_unconfigured):
    """Async HTTP client for an unconfigured app."""
    async with AsyncClient(
        transport=ASGITransport(app=app_unconfigured),
        base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
async def client_with_auth(app_with_auth):
    """Async HTTP client for an auth-enabled app."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_auth),
        base_url="http://test",
    ) as c:
        yield c
