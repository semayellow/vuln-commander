import re
from datetime import datetime, timedelta, UTC

import secrets
from fastapi.security import HTTPBasicCredentials
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.utils import exception, log

from api.src.v1.auth.models.token_model import RefreshToken
from shared.schemas.auth import TokenResponseSchema
from api.src.v1.auth.repositories.token_repository import TokenRepository

from api.src.v1.user.models.user_model import User
from api.src.v1.user.repositories.user_repository import UserRepository

from api.src.v1.connector.models.connector_model import Connector
from api.src.v1.connector.repositories.connector_repository import ConnectorRepository


from api.src.v1.auth.services.utils import (
    is_valid_password,
    encode_access_token,
    decode_access_token
)


class AuthenticationService:
    def __init__(self, session: AsyncSession) -> None:
        self._user_repository = UserRepository(session)
        self._connector_repository = ConnectorRepository(session)
        self._token_repository = TokenRepository(session)

    async def generate_jwt(self, credentials: HTTPBasicCredentials) -> TokenResponseSchema:
        if re.match(re.compile('[^@]+@[^@]+\.[^@]+'), credentials.username):
            entity = await self._user_repository.get_user_by_email(credentials.username)
        else:
            entity = await self._connector_repository.get_connector_by_uuid(credentials.username)

        if not entity:
            raise exception.auth.bad_credentials()

        if not await is_valid_password(credentials.password, entity.password):
            raise exception.auth.bad_credentials()

        created_ad = datetime.now(UTC)
        access_token_expire = (created_ad + timedelta(minutes=5)).timestamp()

        refresh_token = await self._create_or_update_refresh_token(created_ad, entity)
        access_token = await encode_access_token(entity, created_ad.timestamp(), access_token_expire)

        return TokenResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token.value,
            token_type='Bearer',
            expire=access_token_expire
        )

    async def renew_jwt(self, access_token: str, refresh_token: str) -> TokenResponseSchema:
        entity = await self._get_entity(access_token)

        if not (token := await self._token_repository.get_refresh_token_by_entity(entity)):
            raise exception.token.refresh_token_not_found()

        if token.value != refresh_token:
            raise exception.token.invalid_refresh_token()

        if (token.expired_at.timestamp() - datetime.now(UTC).timestamp()) <= 0:
            raise exception.token.refresh_token_expired()

        created_ad = datetime.now(UTC)
        access_token_expire = (created_ad + timedelta(minutes=5)).timestamp()

        refresh_token = await self._create_or_update_refresh_token(created_ad, entity)
        access_token = await encode_access_token(entity, created_ad.timestamp(), access_token_expire)

        return TokenResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token.value,
            token_type='Bearer',
            expire=access_token_expire
        )

    async def _create_or_update_refresh_token(self, created_at: datetime, entity: User | RefreshToken) -> RefreshToken:
        expire = created_at + timedelta(minutes=30)
        value = secrets.token_urlsafe(64)

        if token := await self._token_repository.get_refresh_token_by_entity(entity):
            token = await self._token_repository.update_refresh_token(token, value, expire)
        else:
            token = await self._token_repository.create_refresh_token(entity, value, expire)

        return token

    async def recall_refresh_token(self, access_token: str) -> None:
        entity = await self._get_entity(access_token)

        if not (token := await self._token_repository.get_refresh_token_by_entity(entity)):
            raise exception.token.refresh_token_not_found()

        await self._token_repository.delete_refresh_token(token)

    async def _get_entity(self, access_token: str) -> User | Connector:
        access_token = await decode_access_token(access_token)

        if access_token.scope == 'user':
            entity = await self._user_repository.get_user_by_uuid(access_token.id)
        else:
            entity = await self._connector_repository.get_connector_by_uuid(access_token.id)

        if not entity:
            raise exception.auth.bad_credentials()

        return entity
