from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.src.v1.auth.services.utils import hash_password
from api.src.v1.user.models.user_model import User
from shared.schemas.user import UserSchema, UserUpdateSchema


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_user(self, user_schema: UserSchema) -> User:
        data = user_schema.model_dump(mode="python")
        data["password"] = hash_password(data["password"])
        user = User(**data)
        self._session.add(user)
        await self._session.commit()
        await self._session.refresh(user)
        return user

    async def update_user(self, user: User, user_schema: UserUpdateSchema) -> User:
        data = user_schema.model_dump(mode="json")
        if data.get("password"):
            data["password"] = hash_password(data["password"])
        user.set_not_empty_attrs(**data)
        await self._session.commit()
        await self._session.refresh(user)
        return user

    async def get_user_by_uuid(self, user_id: str) -> User | None:
        query = await self._session.execute(select(User).where(User.id == user_id))
        return query.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> User | None:
        query = await self._session.execute(select(User).where(User.email == email))
        return query.scalar_one_or_none()

    async def delete_user(self, user: User) -> None:
        await self._session.delete(user)
