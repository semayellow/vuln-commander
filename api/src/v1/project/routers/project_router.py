from fastapi import APIRouter, Depends, status

from api.src.v1.auth.dependencies.auth_dependencies import service_capabilities, devsecops_capabilities
from shared.schemas.constants import ConnectorType
from shared.schemas.project import ProjectResponseSchema, ProjectSchema
from api.src.v1.project.services.project_service import ProjectService
from api.src.v1.project.dependencies.project_dependencies import get_project_service

router = APIRouter(prefix="/projects")


@router.post(
    "/",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(service_capabilities)]
)
async def create_or_update_project_handler(
    request: ProjectSchema,
    project_service: ProjectService = Depends(get_project_service)
):
    await project_service.create_or_update_project(request)


@router.get(
    "/{connector_type}",
    response_model=list[ProjectResponseSchema] | list[None],
    dependencies=[Depends(devsecops_capabilities)]
)
async def list_projects_handler(
    connector_type: ConnectorType,
    project_service: ProjectService = Depends(get_project_service)
):
    return await project_service.get_projects(connector_type.value)
