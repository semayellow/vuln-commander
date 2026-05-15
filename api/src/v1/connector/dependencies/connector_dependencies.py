from fastapi import Depends
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.v1.connector.services.connector_service import ConnectorService


async def get_connector_service(
    session: AsyncSession = Depends(get_async_session)
) -> ConnectorService:
    return ConnectorService(session=session)
