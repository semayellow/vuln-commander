from typing import Annotated

from fastapi import APIRouter, Depends, Form, status
from fastapi.security import HTTPBasicCredentials, OAuth2PasswordBearer

from shared.schemas.auth import TokenResponseSchema
from api.src.v1.auth.services.auth_service import AuthenticationService
from api.src.v1.auth.dependencies.auth_dependencies import get_auth_service, user_capabilities

oauth2_schema = OAuth2PasswordBearer(tokenUrl="auth/")
router = APIRouter(prefix="/auth")


@router.post(
    "/",
    response_model=TokenResponseSchema,
)
async def login_handler(
    credentials: HTTPBasicCredentials,
    auth_service: AuthenticationService = Depends(get_auth_service)
):
    return await auth_service.generate_jwt(credentials)


@router.post(
    "/refresh",
    response_model=TokenResponseSchema,
    dependencies=[Depends(user_capabilities)]
)
async def renew_jwt_handler(
    refresh_token: Annotated[str, Form()],
    access_token: str = Depends(oauth2_schema),
    auth_service: AuthenticationService = Depends(get_auth_service)
):
    return await auth_service.renew_jwt(access_token, refresh_token)


@router.delete(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(user_capabilities)]
)
async def recall_refresh_token_handler(
    access_token: str = Depends(oauth2_schema),
    auth_service: AuthenticationService = Depends(get_auth_service)
):
    await auth_service.recall_refresh_token(access_token)
