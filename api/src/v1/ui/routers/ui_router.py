from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from api.src.core.utils.config import Config
from api.src.v1.auth.dependencies.auth_dependencies import get_auth_service
from api.src.v1.auth.services.auth_service import AuthenticationService
from api.src.v1.auth.services.web_auth import enforce_web_auth, set_auth_cookies
from api.src.v1.user.dependencies.user_dependencies import get_user_service
from api.src.v1.user.services.user_service import UserService

router = APIRouter()
templates_path = Path(__file__).parent.parent.parent.parent
templates = Jinja2Templates(directory=f"{templates_path}/templates")


@router.get(
    "/",
    response_class=HTMLResponse,
)
async def home(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
):
    auth = await enforce_web_auth(request, auth_service, user_service)
    if auth.redirect:
        return auth.redirect

    content = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "grafana_url": Config.GRAFANA_URL,
            "graylog_url": Config.GRAYLOG_URL,
            "pgadmin_url": Config.PGADMIN_URL,
        },
    )
    if auth.renewed:
        set_auth_cookies(content, auth.renewed)
    return content
