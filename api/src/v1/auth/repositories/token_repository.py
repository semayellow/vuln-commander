from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.v1.user.models.user_model import User
from api.src.v1.auth.models.token_model import RefreshToken
from api.src.v1.connector.models.connector_model import Connector


class TokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_refresh_token_by_entity(self, entity: User | Connector) -> RefreshToken | None:
        query = await self._session.execute(
            select(RefreshToken)
            .where(RefreshToken.entity_id == entity.id)
        )
        return query.scalar_one_or_none()

    async def create_refresh_token(self, entity: User | Connector, value: str, expire: datetime) -> RefreshToken:
        if isinstance(entity, User):
            token = RefreshToken(user_id=entity.id, value=value, expired_at=expire)
        elif isinstance(entity, Connector):
            token = RefreshToken(connector_id=entity.id, value=value, expired_at=expire)

        self._session.add(token)
        await self._session.commit()
        await self._session.refresh(token)
        return token

    async def update_refresh_token(self, token: RefreshToken, value: str, expire: datetime) -> RefreshToken:
        token.value = value
        token.expired_at = expire
        await self._session.commit()
        await self._session.refresh(token)
        return token

    async def delete_refresh_token(self, token: RefreshToken) -> None:
        await self._session.delete(token)
