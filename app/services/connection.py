"""Shared connection testing and application logic for setup and settings."""

import logging
import re

from app.services.env_file import write_env

logger = logging.getLogger(__name__)

# Hostname or IP (with optional port), no schemes or paths
HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+(:\d+)?$")


def validate_host(host: str) -> str | None:
    """Return an error message if host is invalid, else None."""
    host = host.strip()
    if not host:
        return "Server address is required."
    if len(host) > 253:
        return "Server address is too long."
    if not HOST_PATTERN.match(host):
        return "Invalid server address. Use a hostname or IP (e.g., tower.local or 192.168.1.100)."
    return None


def _is_permission_error(exc: Exception) -> bool:
    """Check if an exception indicates a permission/auth error."""
    from unraid_api.exceptions import UnraidAuthenticationError

    if isinstance(exc, UnraidAuthenticationError):
        return True
    msg = str(exc).lower()
    return "forbidden" in msg or "unauthorized" in msg or "permission" in msg


async def check_permissions(client) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Probe API key permissions after a successful connection.

    Returns (missing_required, missing_optional) where each is a list
    of (permission_name, description) tuples.
    DOCKER:READ_ANY is already verified by the connection test query.
    """
    missing_required: list[tuple[str, str]] = []
    missing_optional: list[tuple[str, str]] = []

    # VMS:READ_ANY
    try:
        await client.query("query { vms { domains { id } } }")
    except Exception as e:
        if _is_permission_error(e):
            missing_required.append(("VMS:READ_ANY", "List VMs and state"))

    # INFO:READ_ANY
    try:
        await client.query("query { info { os { hostname } } }")
    except Exception as e:
        if _is_permission_error(e):
            missing_required.append(("INFO:READ_ANY", "System info and metrics"))

    # DOCKER:UPDATE_ANY (optional)
    try:
        await client.start_container("__probe__")
    except Exception as e:
        if _is_permission_error(e):
            missing_optional.append((
                "DOCKER:UPDATE_ANY",
                "Start, stop, and restart containers from the dashboard. "
                "Without this permission, control buttons will be greyed out.",
            ))

    return missing_required, missing_optional


async def test_and_check_connection(
    host: str, api_key: str, verify_ssl: bool
) -> tuple[str | None, list[tuple[str, str]], list[tuple[str, str]]]:
    """Test connection and check permissions.

    Returns (error, missing_required, missing_optional).
    If error is not None, the permission lists may be incomplete.
    """
    from unraid_api import UnraidClient
    from unraid_api.exceptions import (
        UnraidAPIError,
        UnraidAuthenticationError,
        UnraidConnectionError,
        UnraidSSLError,
        UnraidTimeoutError,
    )

    missing_required: list[tuple[str, str]] = []
    missing_optional: list[tuple[str, str]] = []
    error = None

    try:
        async with UnraidClient(host, api_key, verify_ssl=verify_ssl) as client:
            result = await client.query("query { docker { containers { id } } }")
            if "docker" not in result:
                error = "Connection test failed. Check host and API key."
            else:
                missing_required, missing_optional = await check_permissions(client)
    except UnraidAuthenticationError:
        error = "Authentication failed. Check your API key permissions."
    except UnraidSSLError:
        error = "SSL certificate error. Try unchecking 'Verify SSL certificate'."
    except UnraidConnectionError as e:
        error = f"Could not connect to {host}. Is the server reachable? ({e})"
    except UnraidTimeoutError:
        error = f"Connection to {host} timed out."
    except UnraidAPIError as e:
        error = f"API error: {e}"
    except Exception as e:
        logger.exception("Unexpected error during connection test")
        detail = str(e) or type(e).__name__
        error = f"Unexpected error: {detail}"

    return error, missing_required, missing_optional


async def save_and_apply_connection(app, host: str, api_key: str, verify_ssl: bool) -> None:
    """Save connection settings to .env and recreate the Unraid client on app.state."""
    from unraid_api import UnraidClient

    from app.config import get_settings
    from app.services.unraid import UnraidService

    env_path = get_settings().data_dir / ".env"
    write_env(env_path, {
        "UNRAID_HOST": host,
        "UNRAID_API_KEY": api_key,
        "UNRAID_VERIFY_SSL": "true" if verify_ssl else "false",
    })

    get_settings.cache_clear()
    new_settings = get_settings()

    if new_settings.is_configured:
        new_client = UnraidClient(
            new_settings.unraid_host,
            new_settings.unraid_api_key,
            verify_ssl=new_settings.unraid_verify_ssl,
        )
        await new_client._create_session()

        old_client = getattr(app.state, "unraid_client", None)
        if old_client:
            await old_client.close()

        app.state.unraid_client = new_client
        app.state.unraid_service = UnraidService(
            new_client, new_settings.cache_ttl_seconds, server_host=host
        )
        logger.info("Connected to Unraid at %s", host)
