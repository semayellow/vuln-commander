from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasicCredentials, OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates

from api.src.v1.auth.dependencies.auth_dependencies import get_auth_service, user_capabilities
from api.src.v1.auth.services.auth_service import AuthenticationService
from api.src.v1.auth.services.web_auth import (
    clear_auth_cookies,
    login_user,
    logout_user,
    redirect_url,
    set_auth_cookies,
)
from api.src.v1.user.dependencies.user_dependencies import get_user_service
from api.src.v1.user.services.user_service import UserService
from shared.schemas.auth import TokenResponseSchema

oauth2_schema = OAuth2PasswordBearer(tokenUrl="auth/")
router = APIRouter(prefix="/auth")

templates_path = Path(__file__).parent.parent.parent.parent
templates = Jinja2Templates(directory=f"{templates_path}/templates")


@router.get(
    "/",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
    redirect_page: Annotated[str, Query(alias="next")] = "/api/v1/",
):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "redirect_page": redirect_url(redirect_page),
            "error": None,
            "email": None,
        },
    )


@router.post(
    "/login",
    response_class=HTMLResponse,
)
async def web_login_handler(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    redirect_page: Annotated[str, Form()] = "/api/v1/",
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
):
    redirect_page = redirect_url(redirect_page)

    try:
        tokens = await login_user(email, password, auth_service, user_service)
    except HTTPException:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "redirect_page": redirect_page,
                "error": "Invalid email or password.",
                "email": email.strip(),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    redirect = RedirectResponse(url=redirect_page, status_code=status.HTTP_303_SEE_OTHER)
    set_auth_cookies(redirect, tokens)
    return redirect


@router.post("/logout")
async def web_logout_handler(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
):
    await logout_user(request, auth_service)
    redirect = RedirectResponse(url="/api/v1/auth/", status_code=status.HTTP_303_SEE_OTHER)
    clear_auth_cookies(redirect)
    return redirect


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
