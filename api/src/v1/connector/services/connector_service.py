from sqlalchemy.ext.asyncio import AsyncSession

from api.src.core.utils import exception
from api.src.v1.connector.repositories.connector_repository import ConnectorRepository
from shared.schemas.connector import (
    ConnectorSchema,
    ConnectorResponseSchema,
    ConnectorUpdateSchema,
    ConnectorHistorySchema
)


class ConnectorService:
    def __init__(self, session: AsyncSession) -> None:
        self._connector_repository = ConnectorRepository(session)

    async def create_connector(self, request: ConnectorSchema) -> ConnectorResponseSchema:
        if await self._connector_repository.get_connector_by_name(request.name):
            raise exception.generic.duplicate_name('connector')

        connector = await self._connector_repository.create_connector(request)
        return ConnectorResponseSchema(**connector.serialize())

    async def create_or_update_history(self, request_schema: ConnectorHistorySchema) -> None:
        if history := await self._connector_repository.get_history_by_schema(request_schema):
            await self._connector_repository.update_history(history, request_schema)
        else:
            await self._connector_repository.create_history(request_schema)


    async def get_connector(self, connector_id: str) -> ConnectorResponseSchema:
        if not (connector := await self._connector_repository.get_connector_by_uuid(connector_id)):
            raise exception.generic.entity_not_found('connector')

        return ConnectorResponseSchema(**connector.serialize())

    async def get_connector_scope(self, connector_id: str) -> str:
        connector = await self._connector_repository.get_connector_by_uuid(connector_id)
        return connector.scope.value

    async def update_connector(self, connector_id: str, request: ConnectorUpdateSchema) -> ConnectorResponseSchema:
        if request.is_empty():
            raise exception.generic.empty_request_payload('body')

        if not (connector := await self._connector_repository.get_connector_by_uuid(connector_id)):
            raise exception.generic.entity_not_found('connector')

        updated_connector = await self._connector_repository.update_connector(connector, request)
        return ConnectorResponseSchema(**updated_connector.serialize())

    async def delete_connector(self, connector_id: str) -> None:
        if not (connector := await self._connector_repository.get_connector_by_uuid(connector_id)):
            raise exception.generic.entity_not_found('connector')

        await self._connector_repository.delete_connector(connector)

