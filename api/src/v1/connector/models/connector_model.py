import uuid
from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import DateTime, ForeignKey

from api.src.v1.connector.constants import(
    ConnectorScope,
    ConnectorType,
    ConnectorLastRunStatus
)
from api.src.core.orm.base import (
    Base,
    created_at,
    updated_at,
    gen_uuid
)


class Connector(Base):
    __tablename__ = 'vc_connector'

    id: Mapped[gen_uuid]
    name: Mapped[str] = mapped_column(nullable=False, unique=True)
    password: Mapped[bytes] = mapped_column(nullable=False)
    scope: Mapped[ConnectorScope]
    type: Mapped[ConnectorType]
    created_at: Mapped[created_at]
    updated_at: Mapped[updated_at]
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    is_running: Mapped[bool] = mapped_column(nullable=False, default=False)
    last_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[ConnectorLastRunStatus] = mapped_column(nullable=True)
    debug: Mapped[str] = mapped_column(nullable=True)

    refresh_token: Mapped['RefreshToken'] = relationship(back_populates='connector', uselist=False)

    def serialize(self) -> dict[str, str | datetime]:
        return {
            'name': self.name,
            'scope': self.scope.value,
            'type': self.type.value,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_running': self.is_running,
            'is_active': self.is_active,
            'last_run_at': self.last_run_at,
            'last_run_status': self.last_run_status,
            'debug': self.debug
        }


class ConnectorScanHistory(Base):
    __tablename__ = 'vc_connector_scan_history'

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('vc_project.id'), nullable=False)
    connector_type: Mapped[ConnectorType]
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_commit_hash: Mapped[str] = mapped_column(nullable=False)
    info: Mapped[int] = mapped_column(nullable=True)
    low: Mapped[int] = mapped_column(nullable=True)
    medium: Mapped[int] = mapped_column(nullable=True)
    high: Mapped[int] = mapped_column(nullable=True)
    critical: Mapped[int] = mapped_column(nullable=True)
