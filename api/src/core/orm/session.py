import traceback

from fastapi import HTTPException

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker
)

from api.src.core.utils import (
    Config,
    exception,
    log
)


async_engine = create_async_engine(Config.PSQL_CONNECTION)


async def get_async_session():
    async_session = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception as error:
            await session.rollback()

            if isinstance(error, HTTPException):
                raise error

            log.error(f'Unspecified exception: {traceback.format_exc()}')
            raise exception.generic.internal_server_error()

        finally:
            await session.close()
