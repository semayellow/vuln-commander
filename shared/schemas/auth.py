from datetime import UTC, datetime

from pydantic import BaseModel, Field


class TokenSchema(BaseModel):
    id: str = Field(alias="sub")
    created_ad: float = Field(alias="iat")
    expire: float = Field(alias="expire")
    scope: str

    async def is_expired(self) -> bool:
        return (self.expire - datetime.now(UTC).timestamp()) <= 0


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str | None
    token_type: str
    expire: float
