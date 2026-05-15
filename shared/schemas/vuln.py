import hashlib
import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from shared.schemas.constants import ConnectorType, VulnSeverity, VulnStatus


class VulnSchema(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    project_id: str
    last_commit_hash: str
    created_at: datetime
    connector_type: ConnectorType
    severity: VulnSeverity
    status: VulnStatus
    filepath: str
    line: str
    code_snippet: str
    hash: str = Field(default=None)
    custom_fields: dict | None = Field(default=None)

    @field_serializer("hash")
    def generate_hash(self, _, _info) -> str:
        return hashlib.md5(
            f"{self.project_id},"
            f"{self.connector_type},"
            f"{self.severity},"
            f"{self.filepath},"
            f"{self.line},"
            f"{json.dumps(self.custom_fields)}".encode(),
        ).hexdigest()


class VulnsSchema(BaseModel):
    objects: list[VulnSchema]


class VulnResponseSchema(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    project_id: str
    created_at: datetime
    connector_type: ConnectorType
    severity: VulnSeverity
    status: VulnStatus
    filepath: str
    line: int
    code_snippet: str
    custom_fields: dict | None = Field(default=None)
