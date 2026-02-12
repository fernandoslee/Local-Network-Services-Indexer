import base64
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Optional HTTP Basic Auth. Skips auth for setup (when unconfigured) and health checks."""

    # Paths that never require auth
    PUBLIC_PATHS = {"/api/ping"}
    # Paths that skip auth when app is not yet configured
    SETUP_PATHS = {"/setup"}
    # Static files prefix
    STATIC_PREFIX = "/static/"

    def __init__(self, app, get_settings_fn):
        super().__init__(app)
        self._get_settings = get_settings_fn

    async def dispatch(self, request: Request, call_next) -> Response:
        settings = self._get_settings()

        if not settings.is_auth_configured:
            return await call_next(request)

        path = request.url.path

        # Always allow public paths and static files
        if path in self.PUBLIC_PATHS or path.startswith(self.STATIC_PREFIX):
            return await call_next(request)

        # Allow setup when app is not configured
        if path in self.SETUP_PATHS and not settings.is_configured:
            return await call_next(request)

        # Check Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = decoded.split(":", 1)
                if (
                    secrets.compare_digest(username, settings.auth_username)
                    and secrets.compare_digest(password, settings.auth_password)
                ):
                    return await call_next(request)
            except Exception:
                pass

        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Services Indexer"'},
            content="Unauthorized",
        )
