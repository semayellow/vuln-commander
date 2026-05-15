from fastapi import Depends
from sqlalchemy.ext.asyncio import  AsyncSession

from api.src.core.orm.session import get_async_session
from api.src.v1.vuln.services.vuln_service import VulnService


async def get_vuln_service(
    session: AsyncSession = Depends(get_async_session)
) -> VulnService:
    return VulnService(session=session)
