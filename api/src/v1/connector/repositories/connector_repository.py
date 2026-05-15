from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.src.v1.auth.services.utils import hash_password
from api.src.v1.connector.models.connector_model import Connector, ConnectorScanHistory
from shared.schemas.connector import (
    ConnectorHistorySchema,
    ConnectorSchema,
    ConnectorUpdateSchema,
)


class ConnectorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_connector(self, connector_schema: ConnectorSchema) -> Connector:
        data = connector_schema.model_dump(mode="python")
        data["password"] = hash_password(data["password"])
        connector = Connector(**data)
        self._session.add(connector)
        await self._session.commit()
        await self._session.refresh(connector)
        return connector

    async def create_history(self, history_schema: ConnectorHistorySchema) -> None:
        history = ConnectorScanHistory(**history_schema.model_dump())
        self._session.add(history)
        await self._session.commit()

    async def update_history(self, history: ConnectorScanHistory, history_schema: ConnectorHistorySchema) -> None:
        history.set_not_empty_attrs(**history_schema.model_dump())
        self._session.add(history)
        await self._session.commit()

    async def get_history_by_schema(self, history_schema: ConnectorHistorySchema) -> ConnectorScanHistory | None:
        query = await self._session.execute(
            select(ConnectorScanHistory)
            .where(
                and_(
                    ConnectorScanHistory.project_id == history_schema.project_id,
                    ConnectorScanHistory.connector_type == history_schema.connector_type
                )
            )
        )
        return query.scalar_one_or_none()

    async def get_connector_by_name(self, connector_name: str) -> Connector | None:
        query = await self._session.execute(
            select(Connector)
            .where(Connector.name == connector_name)
        )
        return query.scalar_one_or_none()

    async def get_connector_by_uuid(self, connector_uuid: str) -> Connector | None:
        query = await self._session.execute(
            select(Connector)
            .where(Connector.id == connector_uuid)
        )
        return query.scalar_one_or_none()

    async def update_connector(self, connector: Connector, connector_schema: ConnectorUpdateSchema) -> Connector:
        connector.set_not_empty_attrs(**connector_schema.model_dump(mode='json'))
        await self._session.commit()
        await self._session.refresh(connector)
        return connector

    async def delete_connector(self, connector: Connector) -> None:
        await self._session.delete(connector)
