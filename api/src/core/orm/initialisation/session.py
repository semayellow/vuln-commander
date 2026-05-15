import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.src.core.orm.initialisation.create_accounts import run_create_accounts
from api.src.core.orm.session import async_engine
from api.src.v1.auth.models.token_model import RefreshToken  # noqa: F401
from api.src.v1.connector.models.connector_model import Connector  # noqa: F401
from api.src.v1.user.models.user_model import User  # noqa: F401


async def main() -> None:
    async_session = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        await run_create_accounts(session)


if __name__ == '__main__':
    asyncio.run(main())
