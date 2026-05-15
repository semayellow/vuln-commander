

from sqlalchemy.ext.asyncio import AsyncSession

from api.src.core.utils import log, exception
from api.src.v1.vuln.repositories.vuln_repository import VulnRepository
from api.src.v1.project.repositories.project_repository import ProjectRepository
from shared.schemas.vuln import VulnSchema
from api.src.v1.vuln.constants import VulnStatus, VulnSeverity


class VulnService:
    def __init__(self, session: AsyncSession) -> None:
        self._vuln_repository = VulnRepository(session)
        self._project_repository = ProjectRepository(session)

    async def get_vuln(self, vuln_uuid: str) -> dict:
        vuln = await self._vuln_repository.get_vuln_by_uuid(vuln_uuid)
        return vuln.serialize()

    async def get_related_vuln_ids_by_vuln_id(self, vuln_id: str) -> list[str]:
        vuln = await self._vuln_repository.get_vuln_by_uuid(vuln_id)
        project = await self._project_repository.get_project_by_uuid(str(vuln.project_id))
        return [
            str(vuln.get('id')) for vuln in
            await self.get_vulns_by_project_name(project.name)
        ]

    async def get_vulns_by_project_name(self, project_name: str) -> list[dict]:
        project = await self._project_repository.get_project_by_name(project_name)
        vulns = await self._vuln_repository.get_vulns(str(project.id))

        return [
            {
                'id': vuln.id,
                'severity': vuln.severity.value.upper(),
                'status': vuln.status.value.upper(),
                'created_at': vuln.created_at,
                'closed_at': vuln.closed_at,
                'control_type': vuln.connector_type.value.upper(),
                'filepath': vuln.filepath.replace('no info', '-'),
                'line': vuln.line.replace('no info', '-'),
                'code_snippet': vuln.code_snippet.replace('no info', '-')
            } for vuln, in vulns
        ]

    async def bulk_create_vuln(self, request_schema: list[VulnSchema]) -> None:
        for index, vuln in enumerate(request_schema):
            if await self._vuln_repository.get_vuln_by_hash(vuln.model_dump().get('hash')):
                log.warning(f'Vulnerability is already exists {vuln.model_dump()}')
                del request_schema[index]

        await self._vuln_repository.bulk_create_vuln(request_schema)

    async def bulk_delete_vuln(self, request_schema: list[str]) -> None:
        await self._validate_vuln_hashes(request_schema)
        await self._vuln_repository.bulk_delete_vuln(request_schema)

    async def bulk_update_vulns(
        self,
        request_schema: list[str],
        status: VulnStatus | None,
        severity: VulnSeverity | None,
    ) -> None:
        if not status and not severity:
            raise exception.generic.empty_request_payload('query parameters')

        await self._validate_vuln_hashes(request_schema)
        await self._vuln_repository.bulk_update_vuln(request_schema, status, severity)

    # TODO: Перенести в отдельный сервис
    async def create_ticket(
        self,
        request_schema: list[str]
    ) -> None:
        vuln_hashes =[
            (await self._vuln_repository.get_vuln_by_uuid(vuln_id)).hash
            for vuln_id in request_schema
        ]

        await self._validate_vuln_hashes(request_schema)
        await self._vuln_repository.bulk_update_vuln(vuln_hashes, VulnStatus.awaiting_review)


    async def _validate_vuln_hashes(self, vuln_hashes: list[str]) -> None:
        for index, vuln_hash in enumerate(vuln_hashes):
            if not await self._vuln_repository.get_vuln_by_hash(vuln_hash):
                log.warning(f'Vulnerability with hash {vuln_hash} is not exists')
                del vuln_hashes[index]