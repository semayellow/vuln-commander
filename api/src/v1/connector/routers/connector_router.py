import uuid

from fastapi import APIRouter, Depends, status

from api.src.v1.auth.dependencies.auth_dependencies import (
    user_capabilities,
    admin_capabilities,
    devsecops_capabilities
)

from api.src.v1.connector.dependencies.connector_dependencies import get_connector_service
from api.src.v1.connector.services.connector_service import ConnectorService
from shared.schemas.connector import (
    ConnectorHistorySchema,
    ConnectorResponseSchema,
    ConnectorSchema,
    ConnectorUpdateSchema,
)

router = APIRouter(prefix="/connectors")


@router.post(
    "/",
    response_model=ConnectorResponseSchema,
    dependencies=[Depends(admin_capabilities)]
)
async def create_connector_handler(
    request: ConnectorSchema,
    connector_service: ConnectorService = Depends(get_connector_service)
):
    return await connector_service.create_connector(request)

@router.post(
    "/history",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(devsecops_capabilities)]
)
async def create_or_update_connector_scan_history_handler(
    request: ConnectorHistorySchema,
    connector_service: ConnectorService = Depends(get_connector_service)
):
    await connector_service.create_or_update_history(request)


@router.get(
    "/{connector_id}",
    response_model=ConnectorResponseSchema,
    dependencies=[Depends(user_capabilities)]
)
async def get_connector_handler(
    connector_id: uuid.UUID,
    connector_service: ConnectorService = Depends(get_connector_service)
):
    return await connector_service.get_connector(str(connector_id))


@router.put(
    "/{connector_id}",
    response_model=ConnectorResponseSchema,
    dependencies=[Depends(admin_capabilities)]
)
async def update_connector_handler(
    connector_id: uuid.UUID,
    request: ConnectorUpdateSchema,
    connector_service: ConnectorService = Depends(get_connector_service)
):
    return await connector_service.update_connector(str(connector_id), request)


@router.delete(
    "/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(admin_capabilities)]
)
async def delete_connector_handler(
    connector_id: uuid.UUID,
    connector_service: ConnectorService = Depends(get_connector_service)
):
    await connector_service.delete_connector(str(connector_id))
