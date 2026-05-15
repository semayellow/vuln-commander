import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, DateTime, JSON, Column
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects import postgresql

from api.src.v1.connector.constants import ConnectorType
from api.src.v1.vuln.constants import VulnStatus, VulnSeverity
from api.src.core.orm.base import Base, gen_uuid


class Vulnerability(Base):
    __tablename__ = 'vc_vuln'

    id: Mapped[gen_uuid]
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('vc_project.id'))
    hash: Mapped[str] = mapped_column(nullable=False, unique=True)
    last_commit_hash: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    connector_type = Column('connector_type', postgresql.ENUM(ConnectorType, create_type=False), nullable=False)
    severity: Mapped[VulnSeverity]
    status: Mapped[VulnStatus]
    filepath: Mapped[str] = mapped_column(nullable=False)
    line: Mapped[str] = mapped_column(nullable=False)
    code_snippet: Mapped[str] = mapped_column(nullable=False)
    custom_fields: Mapped[dict] = mapped_column(JSON, nullable=True)

    def serialize(self) -> dict[str, str | int | dict]:
        return {
            'project_id': str(self.project_id),
            'created_at': self.created_at,
            'closed_at': self.closed_at,
            'connector_type': self.connector_type,
            'severity': self.severity,
            'status': self.status,
            'filepath': self.filepath,
            'line': self.line,
            'code_snippet': self.code_snippet,
            'custom_fields': self.custom_fields
        }
