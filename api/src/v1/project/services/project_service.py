from sqlalchemy.ext.asyncio import AsyncSession

from shared.schemas.project import ProjectResponseSchema, ProjectSchema
from api.src.v1.project.models.project_model import Project
from api.src.v1.project.repositories.project_repository import ProjectRepository


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self._project_repository = ProjectRepository(session)

    async def create_or_update_project(self, request: ProjectSchema) -> None:
        if project := await self._project_repository.get_project_by_name(request.project.name):
            await self._update_project(project, request)
        else:
            await self._project_repository.create_project(request)

    async def _update_project(self, project: Project, project_schema: ProjectSchema) -> None:
        await self._project_repository.update_project(project, project_schema.project)
        commit = await self._project_repository.get_commit_by_project(project)
        await self._project_repository.update_commit(commit, project_schema.last_commit)

    async def get_projects(self, connector_type: str) -> list[ProjectResponseSchema] | list[None]:
        if not (projects := await self._project_repository.get_projects_for_scanning(connector_type)):
            return list()

        return [
            ProjectResponseSchema(
                project_id=project.id,
                name=project.name,
                clone_url=project.clone_url,
                last_commit_hash=commit_hash,
                vulns={vuln.get('hash'): vuln.get('status') for vuln in vulns} if vulns else None
            )
            for project, commit_hash, vulns in projects
        ]
