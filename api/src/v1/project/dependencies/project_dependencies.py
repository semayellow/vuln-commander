from fastapi import Depends
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.v1.project.services.project_service import ProjectService


async def get_project_service(
    session: AsyncSession = Depends(get_async_session)
) -> ProjectService:
    return ProjectService(session=session)
