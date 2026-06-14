from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.v1.ui.services.ui_service import UIService


async def get_ui_service(session: AsyncSession = Depends(get_async_session)) -> UIService:
    return UIService(session=session)
