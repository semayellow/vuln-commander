from datetime import datetime

from pydantic import BaseModel, Field

from shared.schemas.constants import UserTeam


class UserSchema(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    team: UserTeam


class UserUpdateSchema(UserSchema):
    first_name: str | None = Field(default=None)
    last_name: str | None = Field(default=None)
    email: str | None = Field(default=None)
    password: str | None = Field(default=None)
    team: UserTeam | None = Field(default=None)

    def is_empty(self) -> bool:
        if not any(
            [
                self.first_name,
                self.last_name,
                self.email,
                self.password,
                self.team,
            ]
        ):
            return True


class UserResponseSchema(BaseModel):
    first_name: str
    last_name: str
    email: str
    team: UserTeam
    created_at: datetime
    updated_at: datetime
    is_active: bool
