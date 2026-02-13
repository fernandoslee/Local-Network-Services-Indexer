import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.dependencies import get_docker_service, get_unraid_service
from app.main import templates
from app.services.docker import DockerService
from app.services.unraid import UnraidService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


@router.get("/containers", response_class=HTMLResponse)
async def containers_partial(
    request: Request,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected to Unraid server.</p>")
    data = await service.get_all_data()
    compact = view == "compact"
    template = "partials/containers_compact.html" if compact else "partials/containers_section.html"
    return templates.TemplateResponse(template, {
        "request": request,
        "containers": data.containers,
        "error": data.error,
        "can_control": data.can_control_containers,
    })


@router.get("/vms", response_class=HTMLResponse)
async def vms_partial(
    request: Request,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected to Unraid server.</p>")
    data = await service.get_all_data()
    compact = view == "compact"
    template = "partials/vms_compact.html" if compact else "partials/vms_section.html"
    return templates.TemplateResponse(template, {
        "request": request,
        "vms": data.vms,
        "error": data.error,
    })


@router.get("/system", response_class=HTMLResponse)
async def system_partial(
    request: Request,
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected to Unraid server.</p>")
    data = await service.get_all_data()
    return templates.TemplateResponse("partials/system_info.html", {
        "request": request,
        "system_info": data.system_info,
        "system_metrics": data.system_metrics,
        "error": data.error,
    })


async def _container_action_response(
    request: Request,
    view: str,
    service: UnraidService,
) -> HTMLResponse:
    data = await service.get_all_data()
    compact = view == "compact"
    template = "partials/containers_compact.html" if compact else "partials/containers_section.html"
    return templates.TemplateResponse(template, {
        "request": request,
        "containers": data.containers,
        "error": data.error,
        "can_control": service.can_control_containers,
    })


@router.post("/containers/start", response_class=HTMLResponse)
async def container_start(
    request: Request,
    id: str,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected.</p>", status_code=503)
    try:
        await service.start_container(id)
    except Exception as e:
        logger.error("Failed to start container %s: %s", id, e)
    return await _container_action_response(request, view, service)


@router.post("/containers/stop", response_class=HTMLResponse)
async def container_stop(
    request: Request,
    id: str,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected.</p>", status_code=503)
    try:
        await service.stop_container(id)
    except Exception as e:
        logger.error("Failed to stop container %s: %s", id, e)
    return await _container_action_response(request, view, service)


@router.post("/containers/restart", response_class=HTMLResponse)
async def container_restart(
    request: Request,
    id: str,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return HTMLResponse("<p>Not connected.</p>", status_code=503)
    try:
        await service.restart_container(id)
    except Exception as e:
        logger.error("Failed to restart container %s: %s", id, e)
    return await _container_action_response(request, view, service)


@router.get("/containers/logs", response_class=HTMLResponse)
async def container_logs(
    request: Request,
    id: str,
    tail: int = 100,
    docker_service: DockerService | None = Depends(get_docker_service),
):
    if docker_service is None:
        return templates.TemplateResponse("partials/container_logs.html", {
            "request": request,
            "lines": [],
            "error": (
                "Docker socket not available. "
                "Mount it in docker-compose.yml: "
                "/var/run/docker.sock:/var/run/docker.sock:ro"
            ),
        })
    error = None
    lines = []
    try:
        lines = await docker_service.get_container_logs(id, tail=tail)
    except Exception as e:
        logger.error("Failed to fetch logs for %s: %s", id, e)
        error = str(e)
    return templates.TemplateResponse("partials/container_logs.html", {
        "request": request,
        "lines": lines,
        "error": error,
    })


@router.get("/health", response_class=HTMLResponse)
async def health_partial(
    request: Request,
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return templates.TemplateResponse("partials/connection_status.html", {
            "request": request,
            "connected": False,
            "server_name": "Not configured",
        })
    data = await service.get_all_data()
    return templates.TemplateResponse("partials/connection_status.html", {
        "request": request,
        "connected": data.error is None,
        "server_name": data.system_info.hostname if data.system_info else "Unknown",
        "error": data.error,
    })
