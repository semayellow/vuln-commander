from dataclasses import dataclass
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.security import HTTPBasicCredentials

from api.src.core.utils import Config, exception
from api.src.v1.auth.services.auth_service import AuthenticationService
from api.src.v1.auth.services.utils import decode_access_token
from api.src.v1.user.services.user_service import UserService
from shared.schemas.auth import TokenResponseSchema

WEB_ACCESS_TOKEN_MINUTES = 15 * 60
WEB_REFRESH_TOKEN_MINUTES = 30 * 60
DEFAULT_NEXT_URL = "/api/v1/"


@dataclass
class WebAuthResult:
    renewed: TokenResponseSchema | None = None
    redirect: RedirectResponse | None = None


def redirect_url(raw: str | None, default: str = DEFAULT_NEXT_URL) -> str:
    if not raw or not raw.startswith("/"):
        return default
    if not raw.startswith("/api/v1/"):
        return default
    if raw.startswith("/api/v1/auth/"):
        return default
    return raw


def redirect_page_from_request(request: Request) -> str:
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"
    return redirect_url(path)


def login_redirect(request: Request) -> RedirectResponse:
    redirect_page = redirect_page_from_request(request)
    return RedirectResponse(
        url=f"/api/v1/auth/?redirect_page={quote(redirect_page, safe='')}",
        status_code=302,
    )


def set_auth_cookies(response: Response, tokens: TokenResponseSchema) -> None:
    response.set_cookie(
        key=Config.ACCESS_TOKEN_COOKIE,
        value=tokens.access_token,
        httponly=True,
        secure=Config.COOKIE_SECURE,
        samesite="lax",
        max_age=WEB_ACCESS_TOKEN_MINUTES,
        path="/",
    )
    if tokens.refresh_token:
        response.set_cookie(
            key=Config.REFRESH_TOKEN_COOKIE,
            value=tokens.refresh_token,
            httponly=True,
            secure=Config.COOKIE_SECURE,
            samesite="lax",
            max_age=WEB_REFRESH_TOKEN_MINUTES,
            path="/",
        )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(key=Config.ACCESS_TOKEN_COOKIE, path="/")
    response.delete_cookie(key=Config.REFRESH_TOKEN_COOKIE, path="/")


async def validate_session(
    access_token: str,
    user_service: UserService,
) -> bool:
    token = await decode_access_token(access_token)
    if await token.is_expired():
        return False
    if token.scope != "user":
        return False

    user = await user_service.get_user(token.id)
    if not user.is_active:
        raise exception.generic.inactive_entity("user")

    return True


async def enforce_web_auth(
    request: Request,
    auth_service: AuthenticationService,
    user_service: UserService,
) -> WebAuthResult:
    access_token = request.cookies.get(Config.ACCESS_TOKEN_COOKIE)
    refresh_token = request.cookies.get(Config.REFRESH_TOKEN_COOKIE)

    if access_token:
        if await validate_session(access_token, user_service):
            return WebAuthResult()

        if refresh_token:
            tokens = await auth_service.renew_jwt(
                access_token,
                refresh_token,
                access_token_minutes=WEB_ACCESS_TOKEN_MINUTES,
                refresh_token_minutes=WEB_REFRESH_TOKEN_MINUTES,
            )
            await validate_session(tokens.access_token, user_service)
            return WebAuthResult(renewed=tokens)

    return WebAuthResult(redirect=login_redirect(request))


async def login_user(
    email: str,
    password: str,
    auth_service: AuthenticationService,
    user_service: UserService,
) -> TokenResponseSchema:
    credentials = HTTPBasicCredentials(username=email.strip(), password=password)
    tokens = await auth_service.generate_jwt(
        credentials,
        access_token_minutes=WEB_ACCESS_TOKEN_MINUTES,
        refresh_token_minutes=WEB_REFRESH_TOKEN_MINUTES,
    )
    if not await validate_session(tokens.access_token, user_service):
        raise exception.auth.bad_credentials()

    return tokens


async def logout_user(
    request: Request,
    auth_service: AuthenticationService,
) -> None:
    access_token = request.cookies.get(Config.ACCESS_TOKEN_COOKIE)
    if not access_token:
        return

    await auth_service.recall_refresh_token(access_token)
