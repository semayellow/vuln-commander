from uuid import UUID
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from api.src.v1.auth.dependencies.auth_dependencies import devsecops_capabilities
from shared.schemas.vuln import VulnSchema
from api.src.v1.vuln.services.vuln_service import VulnService
from api.src.v1.vuln.dependencies.vuln_dependencies import get_vuln_service
from api.src.v1.vuln.constants import VulnStatus, VulnSeverity

router = APIRouter(prefix="/vuln")
templates_path = Path(__file__).parent.parent.parent.parent
templates = Jinja2Templates(directory=f"{templates_path}/templates")


@router.get(
    "/list/{project_name}"
)
async def get_vuln(
    project_name: str,
    vuln_service: VulnService = Depends(get_vuln_service),
):
    return await vuln_service.get_vulns_by_project_name(project_name)

@router.get(
    "/{vuln_id}"
)
async def get_vuln(
    vuln_id: UUID,
    vuln_service: VulnService = Depends(get_vuln_service),
):
    return await vuln_service.get_vuln(str(vuln_id))



@router.post(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(devsecops_capabilities)]
)
async def bulk_create_vuln_handler(
    request: list[VulnSchema],
    vuln_service: VulnService = Depends(get_vuln_service)
):
    await vuln_service.bulk_create_vuln(request)


@router.delete(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(devsecops_capabilities)]
)
async def bulk_delete_vuln_handler(
    request: list[str],
    vuln_service: VulnService = Depends(get_vuln_service)
):
    await vuln_service.bulk_delete_vuln(request)


@router.put(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(devsecops_capabilities)]
)
async def update_vuln_handler(
    request: list[str],
    status: VulnStatus | None = Query(None),
    severity: VulnSeverity | None = Query(None),
    vuln_service: VulnService = Depends(get_vuln_service)
):
    await vuln_service.bulk_update_vulns(request, status, severity)


@router.get(
    "/manage/{project_name}",
    response_class=HTMLResponse
)
async def update_vuln_handler(
    request: Request,
    project_name: str
):
    return templates.TemplateResponse(
        'vuln_management.html',
        {
            'request': request,
            'project_name': project_name
        }
    )


@router.get(
    "/details/{vuln_id}",
    response_class=HTMLResponse
)
async def update_vuln_handler(
    request: Request,
    vuln_id: str,
    vuln_service: VulnService = Depends(get_vuln_service)
):
    related_vuln_ids = await vuln_service.get_related_vuln_ids_by_vuln_id(vuln_id)
    return templates.TemplateResponse(
        'vuln_details.html',
        {
            'request': request,
            'vuln_id': vuln_id,
            'all_vuln_ids': related_vuln_ids
        }
    )

# TODO: Перенести в отдельный сервис
@router.post(
    "/false_positive",
    status_code=status.HTTP_204_NO_CONTENT
)
async def update_vuln_handler(
    request: list[str],
    vuln_service: VulnService = Depends(get_vuln_service)
):
    await vuln_service.create_ticket(request)
