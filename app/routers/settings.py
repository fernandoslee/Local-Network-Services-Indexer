import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.main import templates
from app.services.env_file import write_env

logger = logging.getLogger(__name__)

router = APIRouter()


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

    # Use existing key if none provided
    effective_key = api_key.strip() if api_key.strip() else settings.unraid_api_key
    if not effective_key:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, host=host, masked_key="",
                              verify_ssl=verify_ssl, error="API key is required."),
        )

    # Test the connection
    error = None
    try:
        async with UnraidClient(host, effective_key, verify_ssl=verify_ssl) as client:
            connected = await client.test_connection()
            if not connected:
                error = "Connection test failed. Check host and API key."
    except UnraidAuthenticationError:
        error = "Authentication failed. Check your API key (requires ADMIN role)."
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
            new_client, new_settings.cache_ttl_seconds
        )
        logger.info("Reconnected to Unraid at %s via settings", host)

    return templates.TemplateResponse(
        "settings.html",
        _settings_context(request, success="Connection successful. Settings saved."),
    )


@router.post("/settings/auth", response_class=HTMLResponse)
async def settings_auth_submit(
    request: Request,
    auth_enabled: bool = Form(False),
    auth_username: str = Form("admin"),
    auth_password: str = Form(""),
):
    settings = get_settings()

    # Use existing password if none provided
    effective_password = auth_password if auth_password else settings.auth_password

    if auth_enabled and not effective_password:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, error="Password is required to enable authentication."),
        )

    env_path = settings.data_dir / ".env"
    write_env(env_path, {
        "AUTH_ENABLED": "true" if auth_enabled else "false",
        "AUTH_USERNAME": auth_username.strip() or "admin",
        "AUTH_PASSWORD": effective_password,
    })

    get_settings.cache_clear()

    return templates.TemplateResponse(
        "settings.html",
        _settings_context(request, success="Authentication settings saved."),
    )
