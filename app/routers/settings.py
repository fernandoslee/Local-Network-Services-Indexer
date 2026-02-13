import logging
import re

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.main import templates
from app.services.docker import DockerService
from app.services.env_file import write_env

logger = logging.getLogger(__name__)

router = APIRouter()

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Hostname or IP (with optional port), no schemes or paths
_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+(:\d+)?$")


def _mask_key(key: str) -> str:
    """Show only the last 4 characters of an API key."""
    if len(key) <= 4:
        return key
    return "\u2022" * 8 + key[-4:]


def _settings_context(request, settings=None, **overrides):
    """Build template context for settings page."""
    if settings is None:
        settings = get_settings()
    ctx = {
        "request": request,
        "host": settings.unraid_host,
        "masked_key": _mask_key(settings.unraid_api_key) if settings.unraid_api_key else "",
        "verify_ssl": settings.unraid_verify_ssl,
        "auth_enabled": settings.auth_enabled,
        "auth_username": settings.auth_username,
        "auth_has_password": bool(settings.auth_password),
        "session_max_age": settings.session_max_age,
        "docker_socket_available": DockerService.is_available(),
        "error": None,
        "success": None,
    }
    ctx.update(overrides)
    return ctx


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", _settings_context(request))


@router.post("/settings", response_class=HTMLResponse)
async def settings_submit(
    request: Request,
    host: str = Form(...),
    api_key: str = Form(""),
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

    settings = get_settings()

    host = host.strip()

    # Validate host
    if not host:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, error="Server address is required."),
        )
    if len(host) > 253 or not _HOST_PATTERN.match(host):
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, error="Invalid server address. Use a hostname or IP."),
        )

    # Use existing key if none provided
    effective_key = api_key.strip() if api_key.strip() else settings.unraid_api_key
    if not effective_key:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, host=host, masked_key="",
                              verify_ssl=verify_ssl, error="API key is required."),
        )

    # Test the connection using a lightweight docker query instead of
    # client.test_connection() which queries { online } and requires broader permissions
    error = None
    warnings: list[str] = []
    try:
        async with UnraidClient(host, effective_key, verify_ssl=verify_ssl) as client:
            result = await client.query("query { docker { containers { id } } }")
            if "docker" not in result:
                error = "Connection test failed. Check host and API key."
            else:
                # Check permissions
                from app.routers.setup import _check_permissions
                missing_required, missing_optional = await _check_permissions(client)
                if missing_required:
                    perm_list = ", ".join(p[0] for p in missing_required)
                    error = f"API key is missing required permissions: {perm_list}."
                for perm, desc in missing_optional:
                    warnings.append(f"{perm}: {desc}")
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
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, host=host, masked_key=_mask_key(effective_key),
                              verify_ssl=verify_ssl, error=error),
        )

    # Save configuration (preserves auth settings)
    env_path = settings.data_dir / ".env"
    write_env(env_path, {
        "UNRAID_HOST": host,
        "UNRAID_API_KEY": effective_key,
        "UNRAID_VERIFY_SSL": "true" if verify_ssl else "false",
    })

    # Clear cached settings and recreate client in-process
    get_settings.cache_clear()
    new_settings = get_settings()

    if new_settings.is_configured:
        new_client = UnraidClient(
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
        logger.info("Reconnected to Unraid at %s via settings", host)

    success_msg = "Connection successful. Settings saved."
    if warnings:
        success_msg += " Warning: " + "; ".join(warnings)

    return templates.TemplateResponse(
        "settings.html",
        _settings_context(request, success=success_msg),
    )


VALID_MAX_AGES = {3600, 86400, 604800, 2592000, 7776000, 31536000}


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a hash (bcrypt or legacy plaintext)."""
    import hmac
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    return hmac.compare_digest(plain, hashed)


@router.post("/settings/auth", response_class=HTMLResponse)
async def settings_auth_submit(
    request: Request,
    current_password: str = Form(""),
    auth_enabled: bool = Form(False),
    auth_username: str = Form("admin"),
    auth_password: str = Form(""),
    session_max_age: int = Form(86400),
):
    settings = get_settings()

    # Require current password to make any auth changes
    if settings.is_auth_configured:
        if not current_password or not _verify_password(current_password, settings.auth_password):
            return templates.TemplateResponse(
                "settings.html",
                _settings_context(request, error="Current password is incorrect."),
            )

    # Validate new password length
    if auth_password:
        if len(auth_password) < MIN_PASSWORD_LENGTH:
            return templates.TemplateResponse(
                "settings.html",
                _settings_context(request, error=f"Password must be at least {MIN_PASSWORD_LENGTH} characters."),
            )
        if len(auth_password) > MAX_PASSWORD_LENGTH:
            return templates.TemplateResponse(
                "settings.html",
                _settings_context(request, error=f"Password must be at most {MAX_PASSWORD_LENGTH} characters."),
            )

    # Use existing password hash if none provided
    if auth_password:
        effective_password = bcrypt.hashpw(auth_password.encode(), bcrypt.gensalt()).decode()
    else:
        effective_password = settings.auth_password

    if auth_enabled and not effective_password:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, error="Password is required to enable authentication."),
        )

    # Validate session duration
    if session_max_age not in VALID_MAX_AGES:
        session_max_age = 86400

    env_path = settings.data_dir / ".env"
    write_env(env_path, {
        "AUTH_ENABLED": "true" if auth_enabled else "false",
        "AUTH_USERNAME": auth_username.strip() or "admin",
        "AUTH_PASSWORD": effective_password,
        "SESSION_MAX_AGE": str(session_max_age),
    })

    get_settings.cache_clear()

    # Update live SessionMiddleware max_age
    _update_session_max_age(request.app, session_max_age)

    return templates.TemplateResponse(
        "settings.html",
        _settings_context(request, success="Authentication settings saved."),
    )


def _update_session_max_age(app, max_age: int):
    """Walk the middleware stack and update SessionMiddleware's max_age."""
    from starlette.middleware.sessions import SessionMiddleware
    obj = getattr(app, "middleware_stack", None)
    while obj is not None:
        if isinstance(obj, SessionMiddleware):
            obj.max_age = max_age
            break
        obj = getattr(obj, "app", None)
