from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_, func, and_

from api.src.v1.project.constants import ProjectStatus
from api.src.v1.project.models.project_model import Project, Commit
from api.src.v1.connector.models.connector_model import ConnectorScanHistory
from api.src.v1.vuln.models.vuln_model import Vulnerability
from api.src.v1.vuln.constants import VulnStatus
from shared.schemas.project import (
    ProjectSchema,
    ProjectMetadataSchema,
    CommitMetadataSchema
)


class ProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_project(self, project_schema: ProjectSchema) -> None:
        project = Project(**project_schema.project.model_dump())
        commit = Commit(**project_schema.last_commit.model_dump(mode='python'), project=project)
        self._session.add(project)
        self._session.add(commit)

    async def update_project(self, project: Project, project_schema: ProjectMetadataSchema) -> None:
        project.set_not_empty_attrs(**project_schema.model_dump())
        await self._session.commit()

    async def update_commit(self, commit: Commit, commit_schema: CommitMetadataSchema) -> None:
        commit.set_not_empty_attrs(**commit_schema.model_dump())
        await self._session.commit()

    async def get_project_by_name(self, project_name: str) -> Project | None:
        query = await self._session.execute(
            select(Project)
            .where(Project.name == project_name)
        )
        return query.scalar_one_or_none()

    async def get_project_by_uuid(self, project_id: str) -> Project | None:
        query = await self._session.execute(
            select(Project)
            .where(Project.id == project_id)
        )
        return query.scalar_one_or_none()

    async def get_commit_by_project(self, project: ProjectMetadataSchema) -> Commit | None:
        query = await self._session.execute(
            select(Commit)
            .where(Commit.project_id == project.id)
        )
        return query.scalar_one_or_none()

    async def get_projects_for_scanning(self, connector_type: str) -> list[tuple[Project, str, list[dict[str, str]]]]:
        get_associated_vuln_hashes_func = (
            func.json_strip_nulls(
                func.json_agg(
                    func.json_build_object(
                        'hash', Vulnerability.hash,
                        'status', Vulnerability.status
                    )
                ).filter(Vulnerability.connector_type == connector_type)
            )
        )

        projects_without_changes = (
            select(Project.id)
            .join(Commit, Project.id == Commit.project_id)
            .outerjoin(ConnectorScanHistory, Project.id == ConnectorScanHistory.project_id)
            .where(
                and_(
                    Project.status == ProjectStatus.active.value,
                    ConnectorScanHistory.connector_type == connector_type,
                    Commit.hash == func.coalesce(ConnectorScanHistory.last_commit_hash, '')
                )
            )
        ).subquery()

        query = await self._session.execute(
            select(Project, Commit.hash, get_associated_vuln_hashes_func)
            .join(Commit, Project.id == Commit.project_id)
            .outerjoin(Vulnerability, Project.id == Vulnerability.project_id)
            .outerjoin(ConnectorScanHistory, Project.id == ConnectorScanHistory.project_id)
            .where(Project.id.not_in(projects_without_changes.select()))
            .group_by(Project, Commit.hash)
        )

        return query.all()

    async def count_active_projects(self) -> int | None:
        query = await self._session.execute(
            select(func.count(Project.id)).where(
                Project.status == ProjectStatus.active
            )
        )
        return query.scalar_one_or_none()

    async def get_all_projects_with_comment_and_vulns(self) -> list[tuple[Project, str, int]]:
        open_vuln_count = func.count(Vulnerability.id).filter(
            Vulnerability.status.in_(VulnStatus.get_active_statuses())
        )
        query = await self._session.execute(
            select(Project, Commit.created_at, open_vuln_count)
            .join(Commit, Project.id == Commit.project_id)
            .outerjoin(Vulnerability, Vulnerability.project_id == Project.id)
            .group_by(Project.id, Commit.created_at)
            .order_by(open_vuln_count.desc())
        )
        return query.all()
