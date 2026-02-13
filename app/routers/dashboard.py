from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.dependencies import get_unraid_service
from app.main import templates
from app.services.unraid import UnraidService

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    view: str = "cards",
    service: UnraidService | None = Depends(get_unraid_service),
):
    if service is None:
        return RedirectResponse(url="/setup", status_code=302)

    data = await service.get_all_data()
    compact = view == "compact"

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "containers": data.containers,
        "vms": data.vms,
        "system_info": data.system_info,
        "system_metrics": data.system_metrics,
        "error": data.error,
        "connected": data.error is None,
        "compact": compact,
        "can_control": data.can_control_containers,
        "can_control_vms": data.can_control_vms,
    })
