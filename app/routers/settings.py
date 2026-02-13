import logging

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.auth_utils import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    verify_password,
)
from app.config import get_settings
from app.main import templates
from app.services.connection import (
    save_and_apply_connection,
    test_and_check_connection,
    validate_host,
)
from app.services.docker import DockerService
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
    settings = get_settings()
    host = host.strip()

    # Validate host
    host_error = validate_host(host)
    if host_error:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, error=host_error),
        )

    # Use existing key if none provided
    effective_key = api_key.strip() if api_key.strip() else settings.unraid_api_key
    if not effective_key:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, host=host, masked_key="",
                              verify_ssl=verify_ssl, error="API key is required."),
        )

    error, missing_required, missing_optional = await test_and_check_connection(
        host, effective_key, verify_ssl
    )

    if missing_required and not error:
        perm_list = ", ".join(p[0] for p in missing_required)
        error = f"API key is missing required permissions: {perm_list}."

    if error:
        return templates.TemplateResponse(
            "settings.html",
            _settings_context(request, host=host, masked_key=_mask_key(effective_key),
                              verify_ssl=verify_ssl, error=error),
        )

    await save_and_apply_connection(request.app, host, effective_key, verify_ssl)

    success_msg = "Connection successful. Settings saved."
    if missing_optional:
        warnings = [f"{perm}: {desc}" for perm, desc in missing_optional]
        success_msg += " Warning: " + "; ".join(warnings)

    return templates.TemplateResponse(
        "settings.html",
        _settings_context(request, success=success_msg),
    )


VALID_MAX_AGES = {3600, 86400, 604800, 2592000, 7776000, 31536000}


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
        if not current_password or not verify_password(current_password, settings.auth_password):
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
