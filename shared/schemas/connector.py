from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from shared.schemas.constants import (
    ConnectorLastRunStatus,
    ConnectorScope,
    ConnectorType,
)


class ConnectorSchema(BaseModel):
    name: str
    password: str
    scope: ConnectorScope
    type: ConnectorType


class ConnectorUpdateSchema(BaseModel):
    name: str | None = Field(default=None)
    scope: str | None = Field(default=None)
    type: str | None = Field(default=None)

    def is_empty(self) -> bool:
        if not any([self.name, self.scope, self.type]):
            return True


class ConnectorResponseSchema(BaseModel):
    name: str
    scope: ConnectorScope
    type: ConnectorType
    created_at: datetime
    updated_at: datetime
    is_running: bool
    is_active: bool
    last_run_at: datetime | None
    last_run_status: ConnectorLastRunStatus | None
    debug: str | None


class ConnectorHistorySchema(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    project_id: UUID
    connector_type: ConnectorType
    scanned_at: datetime
    last_commit_hash: str
    info: int | None = Field(default=None)
    low: int | None = Field(default=None)
    medium: int | None = Field(default=None)
    high: int | None = Field(default=None)
    critical: int | None = Field(default=None)
