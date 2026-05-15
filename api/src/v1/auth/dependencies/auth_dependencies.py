from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.core.utils import exception

from api.src.v1.auth.services.utils import decode_access_token
from api.src.v1.auth.services.auth_service import AuthenticationService
from shared.schemas.auth import TokenSchema

from api.src.v1.user.services.user_service import UserService
from api.src.v1.user.dependencies.user_dependencies import get_user_service

from api.src.v1.connector.services.connector_service import ConnectorService
from api.src.v1.connector.dependencies.connector_dependencies import get_connector_service

oauth2_schema = OAuth2PasswordBearer(tokenUrl="auth/")


async def get_auth_service(
    session: AsyncSession = Depends(get_async_session)
) -> AuthenticationService:
    return AuthenticationService(session=session)


async def is_valid_token(
    token: str = Depends(oauth2_schema),
    user_service: UserService = Depends(get_user_service),
    connector_service: ConnectorService = Depends(get_connector_service),
) -> TokenSchema:
    token_obj = await decode_access_token(token)

    if await token_obj.is_expired():
        raise exception.token.access_token_expired()

    if token_obj.scope == 'user':
        entity = await user_service.get_user(token_obj.id)
    else:
        entity = await connector_service.get_connector(token_obj.id)

    if not entity.is_active:
        raise exception.generic.inactive_entity(token_obj.scope)

    return token_obj


class Roles:
    def __init__(self, role_to_check: str) -> None:
        self._role = role_to_check

    async def __call__(
        self,
        token: TokenSchema = Depends(is_valid_token),
        user_service: UserService = Depends(get_user_service),
        connector_service: ConnectorService = Depends(get_connector_service)
    ):
        if token.scope == 'user' and await user_service.get_user_role(token.id) == 'admin':
            return

        if token.scope == 'user' and await user_service.get_user_role(token.id) != self._role:
            raise exception.auth.invalid_capabilities()
        elif token.scope == 'connector' and await connector_service.get_connector_scope(token.id) != self._role:
            raise exception.auth.invalid_capabilities()


admin_capabilities = Roles('admin')
user_capabilities = Roles('user')
service_capabilities = Roles('service')
devsecops_capabilities = Roles('devsecops')
