"""Integration tests for routes using FastAPI TestClient."""

import base64

import pytest
from httpx import ASGITransport, AsyncClient


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


# --- Setup ---

@pytest.mark.asyncio
async def test_setup_page_returns_200_when_unconfigured(client_unconfigured):
    resp = await client_unconfigured.get("/setup")
    assert resp.status_code == 200
    assert "Setup" in resp.text or "setup" in resp.text.lower()

@pytest.mark.asyncio
async def test_setup_redirects_when_configured(client):
    resp = await client.get("/setup", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


# --- Settings ---

@pytest.mark.asyncio
async def test_settings_page_returns_200(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "Server Connection" in resp.text
    assert "Authentication" in resp.text


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
async def test_api_plugins(client):
    resp = await client.get("/api/plugins")
    assert resp.status_code == 200
    assert "Community Applications" in resp.text

@pytest.mark.asyncio
async def test_api_system(client):
    resp = await client.get("/api/system")
    assert resp.status_code == 200
    assert "tower" in resp.text

@pytest.mark.asyncio
async def test_api_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200

@pytest.mark.asyncio
async def test_api_not_connected(client_unconfigured):
    resp = await client_unconfigured.get("/api/containers")
    assert resp.status_code == 200
    assert "Not connected" in resp.text


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


# --- Auth Middleware ---

@pytest.mark.asyncio
async def test_auth_blocks_unauthenticated(client_with_auth):
    resp = await client_with_auth.get("/?view=cards")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers

@pytest.mark.asyncio
async def test_auth_allows_valid_credentials(client_with_auth):
    creds = base64.b64encode(b"admin:secret123").decode()
    resp = await client_with_auth.get("/?view=cards", headers={"Authorization": f"Basic {creds}"})
    assert resp.status_code == 200

@pytest.mark.asyncio
async def test_auth_rejects_wrong_password(client_with_auth):
    creds = base64.b64encode(b"admin:wrong").decode()
    resp = await client_with_auth.get("/?view=cards", headers={"Authorization": f"Basic {creds}"})
    assert resp.status_code == 401

@pytest.mark.asyncio
async def test_auth_rejects_wrong_username(client_with_auth):
    creds = base64.b64encode(b"hacker:secret123").decode()
    resp = await client_with_auth.get("/?view=cards", headers={"Authorization": f"Basic {creds}"})
    assert resp.status_code == 401

@pytest.mark.asyncio
async def test_auth_allows_static_files(client_with_auth):
    resp = await client_with_auth.get("/static/css/app.css")
    assert resp.status_code == 200
