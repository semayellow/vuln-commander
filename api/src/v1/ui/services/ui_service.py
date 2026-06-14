from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from api.src.v1.connector.models.connector_model import Connector
from api.src.v1.project.repositories.project_repository import ProjectRepository
from api.src.v1.vuln.constants import VulnStatus
from api.src.v1.vuln.repositories.vuln_repository import VulnRepository
from api.src.v1.connector.repositories.connector_repository import ConnectorRepository
from api.src.v1.ui.entities import DashboardStats, ProjectRow, ConnectorRow


class UIService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._project_repository = ProjectRepository(session)
        self._vuln_repository = VulnRepository(session)
        self._connector_repository = ConnectorRepository(session)

    async def get_home_page_data(self) -> DashboardStats:
        open_vulns = await self._vuln_repository.count_vulns(VulnStatus.get_active_statuses())
        active_projects = await self._project_repository.count_active_projects()
        connectors = await self._connector_repository.count_connectors()
        scans_today = await self._connector_repository.count_scans_since_the_timestamp(datetime.now(tz=UTC))

        return DashboardStats(
            open_vulnerabilities=open_vulns or 0,
            active_projects=active_projects or 0,
            connectors=connectors or 0,
            scans_today=scans_today or 0,
        )

    async def get_projects_page_data(self) -> list[ProjectRow]:
        projects_info = await self._project_repository.get_all_projects_with_comment_and_vulns()

        return [
            ProjectRow(
                name=project.name,
                team=project.team.value.title(),
                status="Active" if project.status.value == "active" else "Inactive",
                last_commit_date=commit_date,
                open_vulns=vulns_count or 0,
            )
            for project, commit_date, vulns_count in projects_info
        ]

    async def get_connectors_page_data(self) -> list[ConnectorRow]:
        connectors = await self._connector_repository.get_connectors()
        rows: list[ConnectorRow] = []

        for connector in connectors:
            status, status_class = self._format_connector_status(connector)
            rows.append(
                ConnectorRow(
                    name=connector.name,
                    scope=connector.scope.value,
                    status=status,
                    status_class=status_class,
                    last_run=connector.last_run_at or "-",
                )
            )
        return rows

    @staticmethod
    def _format_connector_status(connector: Connector) -> tuple[str, str]:
        if connector.is_running:
            return "Running", "badge badge--success"
        if connector.last_run_status and connector.last_run_status.value == "failure":
            return "Error", "badge badge--error"
        if connector.is_active:
            return "Waiting", "badge badge--secondary"
        return "Inactive", "badge badge--secondary"
