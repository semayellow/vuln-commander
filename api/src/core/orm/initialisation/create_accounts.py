import os
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.src.core.utils import log
from api.src.v1.auth.models.token_model import RefreshToken  # noqa: F401
from api.src.v1.auth.services.utils import hash_password
from api.src.v1.connector.models.connector_model import Connector
from api.src.v1.connector.repositories.connector_repository import ConnectorRepository
from api.src.v1.user.constants import UserRole, UserTeam
from api.src.v1.user.models.user_model import User

from api.src.core.orm.initialisation.util import InitException, get_connectors


async def check_user_count(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(User))
    return int(result.scalar_one())


async def register_admin(session: AsyncSession) -> None:
    if await check_user_count(session) > 0:
        log.info('[VC DataBase Initialization] Skip admin (database already has users)')
        return
    
    email = os.environ.get('ADMIN_EMAIL', '').strip()
    password = os.environ.get('ADMIN_PASSWORD', '').strip()
    
    if not email or not password:
        raise InitException(f'Admin email and password required.')

    firstname = (os.environ.get('ADMIN_FIRST_NAME') or 'Admin').strip() or 'Admin'
    lastname = (os.environ.get('ADMIN_LAST_NAME') or 'User').strip() or 'User'
    team_raw = (os.environ.get('ADMIN_TEAM') or 'ti').strip() or 'ti'
    
    try:
        team = UserTeam(team_raw)
    except ValueError:
        raise InitException(f'Invalid user team: {team_raw}')

    session.add(
        User(
            first_name=firstname,
            last_name=lastname,
            email=email,
            password=hash_password(password),
            role=UserRole.admin,
            team=team,
        )
    )
    await session.commit()
    log.info(f'[VC DataBase Initialization] Created admin user {email}')


async def register_connectors(session: AsyncSession) -> None:
    repo = ConnectorRepository(session)

    for connector in get_connectors():
        env_base = f'CONNECTOR_{connector.env}_'
        password = os.environ.get(f'{env_base}PASSWORD', '').strip()
        connector_uuid_raw = os.environ.get(f'{env_base}UUID', '').strip()

        try:
            connector_uuid = uuid.UUID(connector_uuid_raw)
        except ValueError:
            raise InitException(f'Invalid UUID format for {connector.name} connector.')

        if not password:
            raise InitException(f'Password is required for {connector.name} connector.')

        if await repo.get_connector_by_name(connector.name):
            log.info(f'[VC DataBase Initialization] Connector {connector.name} already exists, skip')
            continue

        session.add(
            Connector(
                id=connector_uuid,
                name=connector.name,
                password=hash_password(password),
                scope=connector.scope,
                type=connector.type,
                is_active=True,
                is_running=False,
            )
        )

        await session.commit()
        log.info(f'[VC DataBase Initialization] Registered connector {connector.name}')


async def run_create_accounts(session: AsyncSession) -> None:
    await register_admin(session)
    await register_connectors(session)
