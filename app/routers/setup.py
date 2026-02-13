import logging
import secrets

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth_utils import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.config import get_settings
from app.main import templates
from app.services.connection import (
    save_and_apply_connection,
    test_and_check_connection,
    validate_host,
)
from app.services.env_file import write_env

logger = logging.getLogger(__name__)

router = APIRouter()


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
    host = host.strip()
    api_key = api_key.strip()

    host_error = validate_host(host)
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

    error, missing_required, missing_optional = await test_and_check_connection(
        host, api_key, verify_ssl
    )

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

    await save_and_apply_connection(request.app, host, api_key, verify_ssl)

    # If optional permissions are missing, show success page with warnings
    if missing_optional:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "step": 3,
            "warnings": missing_optional,
        })

    return RedirectResponse(url="/", status_code=302)
