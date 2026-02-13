import logging
import secrets
import time
from collections import defaultdict

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth_utils import MAX_PASSWORD_LENGTH, verify_password
from app.config import get_settings
from app.main import templates

logger = logging.getLogger(__name__)

router = APIRouter()

# Simple in-memory rate limiter: {ip: [timestamp, ...]}
_login_attempts: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW = 300  # 5 minutes
_RATE_LIMIT_MAX = 10  # max attempts per window


def _is_rate_limited(ip: str) -> bool:
    """Check if an IP has exceeded the login attempt rate limit."""
    now = time.monotonic()
    attempts = _login_attempts[ip]
    # Prune old entries
    _login_attempts[ip] = [t for t in attempts if now - t < _RATE_LIMIT_WINDOW]
    return len(_login_attempts[ip]) >= _RATE_LIMIT_MAX


def _record_attempt(ip: str) -> None:
    _login_attempts[ip].append(time.monotonic())


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("authenticated"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
    })


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    settings = get_settings()

    if not settings.is_auth_configured:
        return RedirectResponse(url="/", status_code=302)

    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if _is_rate_limited(client_ip):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many login attempts. Please try again later.",
        })

    # Enforce max password length to prevent bcrypt DoS
    if len(password) > MAX_PASSWORD_LENGTH:
        _record_attempt(client_ip)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password.",
        })

    # Constant-time username comparison + password verification
    # Always run both to prevent timing-based user enumeration
    username_match = secrets.compare_digest(username, settings.auth_username)
    password_match = verify_password(password, settings.auth_password)
    valid = username_match and password_match

    if not valid:
        _record_attempt(client_ip)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password.",
        })

    # Migrate plaintext password to bcrypt on successful login
    if not settings.auth_password.startswith("$2b$"):
        from app.services.env_file import write_env
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        env_path = settings.data_dir / ".env"
        write_env(env_path, {"AUTH_PASSWORD": hashed})
        get_settings.cache_clear()
        logger.info("Migrated plaintext password to bcrypt hash")

    # Session regeneration: clear old session before setting authenticated
    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = username
    logger.info("User logged in successfully")
    return RedirectResponse(url="/", status_code=302)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
