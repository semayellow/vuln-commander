from sqlalchemy.ext.asyncio import AsyncSession

from api.src.v1.user.repositories.user_repository import UserRepository
from api.src.core.utils import exception
from shared.schemas.user import UserResponseSchema, UserSchema, UserUpdateSchema


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self._user_repository = UserRepository(session)

    async def create_user(self, request_schema: UserSchema) -> UserResponseSchema:
        if await self._user_repository.get_user_by_email(request_schema.email):
            raise exception.generic.duplicate_name('user')

        user = await self._user_repository.create_user(request_schema)
        return UserResponseSchema(**user.serialize())

    async def get_user(self, user_id: str) -> UserResponseSchema:
        if not (user := await self._user_repository.get_user_by_uuid(user_id)):
            raise exception.generic.entity_not_found('user')

        return UserResponseSchema(**user.serialize())

    async def get_user_role(self, user_id: str) -> str:
        user = await self._user_repository.get_user_by_uuid(user_id)
        return user.role.value

    async def update_user(self, user_id: str, request_schema: UserUpdateSchema) -> UserResponseSchema:
        if request_schema.is_empty():
            raise exception.generic.empty_request_payload('body')

        if await self._user_repository.get_user_by_email(request_schema.email):
            raise exception.generic.duplicate_name('user')

        if not (user := await self._user_repository.get_user_by_uuid(user_id)):
            raise exception.generic.entity_not_found('user')

        updated_user = await self._user_repository.update_user(user, request_schema)
        return UserResponseSchema(**updated_user.serialize())

    async def delete_user(self, user_id: str) -> None:
        if not (user := await self._user_repository.get_user_by_uuid(user_id)):
            raise exception.generic.entity_not_found('user')

        await self._user_repository.delete_user(user)
