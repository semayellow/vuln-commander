import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.src.v1.project.constants import ProjectStatus
from api.src.v1.user.constants import UserTeam

from api.src.core.orm.base import Base, gen_uuid


class Project(Base):
    __tablename__ = 'vc_project'

    id: Mapped[gen_uuid]
    team: Mapped[UserTeam] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=True, unique=True)
    default_branch: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[ProjectStatus] = mapped_column(nullable=False)
    clone_url: Mapped[str] = mapped_column(nullable=False)

    commit: Mapped['Commit'] = relationship(back_populates='project', uselist=False)


class Commit(Base):
    __tablename__ = 'vc_commit'

    id: Mapped[gen_uuid]
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('vc_project.id'))
    author: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, unique=False)
    hash: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    project: Mapped['Project'] = relationship(back_populates='commit')
