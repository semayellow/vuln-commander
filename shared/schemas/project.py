from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from shared.schemas.constants import ProjectStatus, UserTeam


class ProjectMetadataSchema(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    team: UserTeam
    name: str
    status: ProjectStatus
    default_branch: str
    clone_url: str


class CommitMetadataSchema(BaseModel):
    author: str
    email: str
    created_at: datetime
    hash: str


class ProjectSchema(BaseModel):
    project: ProjectMetadataSchema
    last_commit: CommitMetadataSchema


class ProjectResponseSchema(BaseModel):
    project_id: UUID
    name: str
    clone_url: str
    last_commit_hash: str
    vulns: dict[str, str] | None
