from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.src.v1.user.constants import UserRole, UserTeam
from api.src.core.orm.base import (
    Base,
    created_at,
    updated_at,
    gen_uuid
)


class User(Base):
    __tablename__ = 'vc_user'

    id: Mapped[gen_uuid]
    created_at: Mapped[created_at]
    updated_at: Mapped[updated_at]
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    first_name: Mapped[str] = mapped_column(nullable=False)
    last_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    password: Mapped[bytes] = mapped_column(nullable=False)
    role: Mapped[UserRole] = mapped_column(nullable=False, default=UserRole.user.value)
    team: Mapped[UserTeam] = mapped_column(nullable=False)

    refresh_token: Mapped['RefreshToken'] = relationship(back_populates='user', uselist=False)

    def serialize(self) -> dict[str, str | datetime]:
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'team': self.team.value,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_active': self.is_active
        }
