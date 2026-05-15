import asyncio
from datetime import datetime, UTC
from typing import Self
from uuid import UUID

import aiohttp
from pydantic import BaseModel

from sdk.src.utils import get_running_loop
from sdk.src.utils.helpers import repeat_request
from sdk.src.utils.config import Config
from sdk.src.utils.models import Credentials
from sdk.src.utils.exceptions import RunTimeException

from shared.schemas.connector import ConnectorHistorySchema
from shared.schemas.constants import ConnectorType, VulnStatus
from shared.schemas.project import ProjectResponseSchema, ProjectSchema
from shared.schemas.vuln import VulnSchema


class VulnCommanderSDK:
    def __init__(
            self,
            connector_id: str,
            connector_password: str,
            trust_env: bool = False,
            verify_ssl: str | None = None,
            proxy: str | None = None,
            connector: aiohttp.BaseConnector | None = None,
    ) -> None:
        """
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Path to SSL certificate
        :param connector: A custom aiohttp connector
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        """
        self._id = connector_id
        self._password = connector_password
        self._proxy = proxy
        self._trust_env = trust_env
        self._verify_ssl = verify_ssl
        self._connector = connector

        self._session: aiohttp.ClientSession | None = None
        self._access_token_expired_at: float | None = None
        self._headers: dict[str, str] | None = None

    async def __aenter__(self) -> Self:
        await self._open_session()
        return self

    async def __aexit__(self, item_type, value, traceback) -> None:
        await self._close_session()

    async def _open_session(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(
                trust_env=self._trust_env,
                connector=self._connector,
                proxy=self._proxy,
                timeout=aiohttp.ClientTimeout(60)
            )

    async def _close_session(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    def _setup_connector(self) -> None:
        if not self._connector and self._verify_ssl:
            event_loop = get_running_loop()
            asyncio.set_event_loop(event_loop)
            self._connector = aiohttp.TCPConnector(
                ssl=self._verify_ssl,
                loop=event_loop,
                keepalive_timeout=30
            )

    async def _make_request(
        self,
        method: str,
        url: str,
        payload: BaseModel | list | None = None,
        is_authorization: bool = False
    ) -> dict | list | None:
        if not is_authorization:
            await self._authenticate()

        response: aiohttp.ClientResponse = await self._session.request(
            method,
            url,
            json=payload.model_dump(mode='json') if isinstance(payload, BaseModel) else payload,
            ssl=True if self._verify_ssl else False,
        )

        if response.status >= 300:
            raise RunTimeException(description=await response.text(), code=response.status)

        return await response.json()

    async def _authenticate(self) -> None:
        if not self._access_token_expired_at:
            await self._update_session_headers()
        elif (self._access_token_expired_at - datetime.now(UTC).timestamp()) <= 0:
            await self._update_session_headers()

    async def _update_session_headers(self) -> None:
        url = f'{Config.API_BASE_URL}/auth'

        payload = Credentials(
            username=self._id,
            password=self._password
        )

        token_response = await self._make_request('POST', url, payload, is_authorization=True)
        access_token = token_response.get('access_token')

        self._access_token_expired_at = token_response.get('expire')
        self._session.headers['Authorization'] = f'Bearer {access_token}'

    async def process_vulns(self, actual_vulns: dict[str, VulnSchema], stored_vulns: dict[str, str] | None) -> None:
        if not stored_vulns:
            await self.bulk_create_vulns([vuln.model_dump(mode='json') for vuln in actual_vulns.values()])
        else:
            await self._synchronize_vulns(actual_vulns, stored_vulns)

    async def _synchronize_vulns(self, actual_vulns: dict[str, VulnSchema], stored_vulns: dict[str, str]) -> None:
        vulns_to_create = [
            vuln.model_dump(mode='json') for vuln_hash, vuln in actual_vulns.items()
            if vuln_hash not in stored_vulns
        ]

        vulns_to_close = [
            vuln_hash for vuln_hash, vuln_status in stored_vulns.items()
            if vuln_hash not in actual_vulns and vuln_status in ('new', 'reopened')
        ]

        vulns_to_reopen = [
            vuln_hash for vuln_hash in actual_vulns.keys()
            if (status := stored_vulns.get(vuln_hash)) and status == 'closed'
        ]

        await self.bulk_create_vulns(vulns_to_create)

        if vulns_to_reopen:
            await self.bulk_update_vulns(vulns_to_reopen, VulnStatus.reopened)

        if vulns_to_close:
            await self.bulk_update_vulns(vulns_to_close, VulnStatus.closed)

    @repeat_request
    async def bulk_create_vulns(self, vulns: list[dict]) -> None:
        url = f'{Config.API_BASE_URL}/vuln'
        await self._make_request('POST', url, vulns)

    @repeat_request
    async def bulk_update_vulns(
        self,
        vuln_hashes: list[str],
        vuln_status: VulnStatus
    ) -> None:
        url = f'{Config.API_BASE_URL}/vuln?status={vuln_status.value}'

        await self._make_request('PUT', url, vuln_hashes)

    @repeat_request
    async def create_or_update_project(self, project: ProjectSchema) -> None:
        url = f'{Config.API_BASE_URL}/projects'
        await self._make_request('POST', url, project)

    async def get_projects(self, connector_type: ConnectorType) -> list[ProjectResponseSchema]:
        url = f'{Config.API_BASE_URL}/projects/{connector_type.value}'

        if projects := await self._make_request('GET', url):
            return [ProjectResponseSchema(**project) for project in projects]
        return []

    async def create_or_update_history(
            self,
            connector_type: ConnectorType,
            project_id: UUID,
            last_commit_hash: str,
            info: int | None = None,
            low: int | None = None,
            medium: int | None = None,
            high: int | None = None,
            critical: int | None = None
    ) -> None:
        connector_history = ConnectorHistorySchema(
            connector_type=connector_type,
            project_id=project_id,
            scanned_at=datetime.now(UTC),
            last_commit_hash=last_commit_hash,
            info=info,
            low=low,
            medium=medium,
            high=high,
            critical=critical
        )

        url = f'{Config.API_BASE_URL}/connectors/history'
        await self._make_request('POST', url, connector_history)
