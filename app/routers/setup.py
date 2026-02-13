import logging
import re
import secrets

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from unraid_api.exceptions import UnraidAPIError, UnraidAuthenticationError

from app.config import get_settings
from app.main import templates
from app.services.env_file import write_env

logger = logging.getLogger(__name__)

router = APIRouter()

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Hostname or IP (with optional port), no schemes or paths
_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+(:\d+)?$")


def _is_permission_error(exc: Exception) -> bool:
    """Check if an exception indicates a permission/auth error."""
    if isinstance(exc, UnraidAuthenticationError):
        return True
    msg = str(exc).lower()
    return "forbidden" in msg or "unauthorized" in msg or "permission" in msg


async def _check_permissions(client) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
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


def _validate_host(host: str) -> str | None:
    """Return an error message if host is invalid, else None."""
    host = host.strip()
    if not host:
        return "Server address is required."
    if len(host) > 253:
        return "Server address is too long."
    if not _HOST_PATTERN.match(host):
        return "Invalid server address. Use a hostname or IP (e.g., tower.local or 192.168.1.100)."
    return None


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    settings = get_settings()

    # Both configured → go to dashboard
    if settings.is_auth_configured and settings.is_configured:
        return RedirectResponse(url="/", status_code=302)

    # Step 1: Create account (no auth yet)
    if not settings.is_auth_configured:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 1,
            "error": None,
            "username": "admin",
        })

    # Step 2: Connect to Unraid (auth done, no connection)
    return templates.TemplateResponse("setup.html", {
        "request": request,
        "step": 2,
        "error": None,
        "host": "",
        "api_key": "",
    })


@router.post("/setup/credentials", response_class=HTMLResponse)
async def setup_credentials(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    # Block if auth is already configured (prevents credential overwrite)
    if get_settings().is_auth_configured:
        return RedirectResponse(url="/", status_code=302)

    username = username.strip()
    error = None

    if not username:
        error = "Username is required."
    elif len(username) > 64:
        error = "Username is too long (max 64 characters)."
    elif len(password) < MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    elif len(password) > MAX_PASSWORD_LENGTH:
        error = f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    elif password != password_confirm:
        error = "Passwords do not match."

    if error:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 1,
            "error": error,
            "username": username,
        })

    # Hash password and generate session secret
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    session_secret = secrets.token_hex(32)

    env_path = get_settings().data_dir / ".env"
    write_env(env_path, {
        "AUTH_ENABLED": "true",
        "AUTH_USERNAME": username,
        "AUTH_PASSWORD": hashed,
        "SESSION_SECRET_KEY": session_secret,
    })
    get_settings.cache_clear()

    # Update the live SessionMiddleware with the new secret key
    _update_session_secret(request.app, session_secret)

    return RedirectResponse(url="/setup", status_code=302)


def _update_session_secret(app, secret: str):
    """Walk the middleware stack and update SessionMiddleware's secret key."""
    import itsdangerous
    from starlette.middleware.sessions import SessionMiddleware
    obj = getattr(app, "middleware_stack", None)
    while obj is not None:
        if isinstance(obj, SessionMiddleware):
            obj.signer = itsdangerous.TimestampSigner(secret)
            break
        obj = getattr(obj, "app", None)


@router.post("/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    host: str = Form(...),
    api_key: str = Form(...),
    verify_ssl: bool = Form(False),
):
    from unraid_api import UnraidClient
    from unraid_api.exceptions import (
        UnraidAuthenticationError,
        UnraidConnectionError,
        UnraidSSLError,
        UnraidTimeoutError,
    )

    from app.services.unraid import UnraidService

    host = host.strip()
    api_key = api_key.strip()

    host_error = _validate_host(host)
    if host_error:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 2,
            "error": host_error,
            "host": host,
            "api_key": "",
        })

    if len(api_key) > 256:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 2,
            "error": "API key is too long.",
            "host": host,
            "api_key": "",
        })

    error = None
    missing_required: list[tuple[str, str]] = []
    missing_optional: list[tuple[str, str]] = []
    try:
        async with UnraidClient(host, api_key, verify_ssl=verify_ssl) as client:
            # Use a lightweight docker query instead of client.test_connection()
            # which queries { online } and requires broader permissions
            result = await client.query("query { docker { containers { id } } }")
            if "docker" not in result:
                error = "Connection test failed. Check host and API key."
            else:
                # Connection works — check all permissions
                missing_required, missing_optional = await _check_permissions(client)
    except UnraidAuthenticationError:
        error = "Authentication failed. Check your API key permissions."
    except UnraidSSLError:
        error = "SSL certificate error. Try unchecking 'Verify SSL certificate'."
    except UnraidConnectionError as e:
        error = f"Could not connect to {host}. Is the server reachable? ({e})"
    except UnraidTimeoutError:
        error = f"Connection to {host} timed out."
    except Exception as e:
        error = f"Unexpected error: {e}"

    if error:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 2,
            "error": error,
            "host": host,
            "api_key": "",  # Don't echo API key back to template
        })

    if missing_required:
        perm_list = ", ".join(p[0] for p in missing_required)
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 2,
            "error": f"API key is missing required permissions: {perm_list}. "
                     "Please update the key in Unraid API settings.",
            "host": host,
            "api_key": "",
        })

    # Save configuration (preserves any existing auth settings)
    env_path = get_settings().data_dir / ".env"
    write_env(env_path, {
        "UNRAID_HOST": host,
        "UNRAID_API_KEY": api_key,
        "UNRAID_VERIFY_SSL": "true" if verify_ssl else "false",
    })

    # Clear cached settings and recreate client in-process
    get_settings.cache_clear()
    new_settings = get_settings()

    if new_settings.is_configured:
        from unraid_api import UnraidClient as UC

        new_client = UC(
            new_settings.unraid_host,
            new_settings.unraid_api_key,
            verify_ssl=new_settings.unraid_verify_ssl,
        )
        await new_client._create_session()

        old_client = getattr(request.app.state, "unraid_client", None)
        if old_client:
            await old_client.close()

        request.app.state.unraid_client = new_client
        request.app.state.unraid_service = UnraidService(
            new_client, new_settings.cache_ttl_seconds, server_host=host
        )
        logger.info("Connected to Unraid at %s via setup", host)

    # If optional permissions are missing, show success page with warnings
    if missing_optional:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 3,
            "warnings": missing_optional,
        })

    return RedirectResponse(url="/", status_code=302)
