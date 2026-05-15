from fastapi import Depends
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.v1.user.services.user_service import UserService


async def get_user_service(
    session: AsyncSession = Depends(get_async_session)
) -> UserService:
    return UserService(session=session)
