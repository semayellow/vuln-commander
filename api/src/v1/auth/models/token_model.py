from uuid import UUID
from datetime import datetime

from sqlalchemy import ForeignKey, DateTime
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.src.core.orm.base import Base, gen_uuid


class RefreshToken(Base):
    __tablename__ = 'vc_refresh_token'

    id: Mapped[gen_uuid]
    user_id: Mapped[UUID] = mapped_column(ForeignKey('vc_user.id'), nullable=True)
    connector_id: Mapped[UUID] = mapped_column(ForeignKey('vc_connector.id'), nullable=True)
    value: Mapped[str] = mapped_column(nullable=False)
    expired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped['User'] = relationship(back_populates='refresh_token', uselist=False)
    connector: Mapped['Connector'] = relationship(back_populates='refresh_token', uselist=False)

    @hybrid_property
    def entity_id(self) -> UUID:
        return self.user_id or self.connector_id