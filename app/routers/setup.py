import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import get_settings
from app.main import templates
from app.services.env_file import write_env

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    settings = get_settings()
    if settings.is_configured:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("setup.html", {
        "request": request,
        "error": None,
        "host": "",
        "api_key": "",
    })


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

    error = None
    try:
        async with UnraidClient(host, api_key, verify_ssl=verify_ssl) as client:
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
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": error,
            "host": host,
            "api_key": api_key,
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
            new_client, new_settings.cache_ttl_seconds
        )
        logger.info("Connected to Unraid at %s via setup", host)

    return RedirectResponse(url="/", status_code=302)
