from enum import Enum

from shared.schemas.constants import UserTeam


class UserRole(Enum):
    user = "user"
    admin = "admin"


__all__ = ["UserRole", "UserTeam"]
