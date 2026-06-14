from sqlalchemy import select, insert, delete, update, bindparam, func
from sqlalchemy.ext.asyncio import AsyncSession

from api.src.v1.vuln.models.vuln_model import Vulnerability
from shared.schemas.vuln import VulnSchema
from api.src.v1.vuln.constants import VulnStatus, VulnSeverity



class VulnRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_vulns(self, project_id: str) -> list[tuple[Vulnerability, ]]:
        query = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.project_id == project_id)
        )
        return query.all()

    async def bulk_create_vuln(self, vulns: list[VulnSchema]) -> None:
        await self._session.execute(
            insert(Vulnerability),
            [vuln.model_dump(mode='python') for vuln in vulns]
        )
        await self._session.commit()

    async def bulk_delete_vuln(self, vuln_hashes: list[str]) -> None:
        await self._session.execute(
            delete(Vulnerability)
            .where(Vulnerability.hash.in_(vuln_hashes))
        )
        await self._session.commit()

    async def bulk_update_vuln(self,
        vuln_hashes: list[str],
        status: VulnStatus | None = None,
        severity: VulnSeverity | None = None,
    ) -> None:
        await self._session.execute(
            update(Vulnerability)
            .execution_options(synchronize_session=False),
            await self._generate_vuln_update_params(vuln_hashes, status, severity)
        )
        await self._session.commit()

    async def get_vuln_by_hash(self, vuln_hash: str) -> Vulnerability | None:
        query = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.hash == vuln_hash)
        )
        return query.scalar_one_or_none()

    async def get_vuln_by_uuid(self, vuln_id: str) -> Vulnerability | None:
        query = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.id == vuln_id)
        )
        return query.scalar_one_or_none()

    async def _generate_vuln_update_params(
        self,
        vuln_hashes: list[str],
        status: VulnStatus | None,
        severity: VulnSeverity | None
    ) -> list[dict]:
        vuln_update_params = []

        if status:
            vuln_update_params.append(('status', status))
        if severity:
            vuln_update_params.append(('severity', severity))

        return [
            dict([('id', (await self.get_vuln_by_hash(vuln_hash)).id), *vuln_update_params])
            for vuln_hash in vuln_hashes
        ]

    async def count_vulns(self, vuln_statuses: list[str]) -> int | None:
        query = await self._session.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status.in_(vuln_statuses)
            )
        )
        return query.scalar_one_or_none()
