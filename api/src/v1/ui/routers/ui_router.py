from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from api.src.core.utils.config import Config
from api.src.v1.auth.dependencies.auth_dependencies import get_auth_service
from api.src.v1.auth.services.auth_service import AuthenticationService
from api.src.v1.auth.services.web_auth import enforce_web_auth, set_auth_cookies
from api.src.v1.ui.dependencies.ui_dependencies import get_ui_service
from api.src.v1.ui.services.ui_service import UIService
from api.src.v1.user.dependencies.user_dependencies import get_user_service
from api.src.v1.user.services.user_service import UserService

router = APIRouter()
templates_path = Path(__file__).parent.parent.parent.parent
templates = Jinja2Templates(directory=f"{templates_path}/templates")


async def _enforce_authentication(
    request: Request,
    template_name: str,
    context: dict,
    auth_service: AuthenticationService,
    user_service: UserService,
):
    auth = await enforce_web_auth(request, auth_service, user_service)
    if auth.redirect:
        return auth.redirect

    user_info = await user_service.get_user_name_and_email(request)
    content = templates.TemplateResponse(
        template_name,
        {
            "request": request,
            "sidebar_user": user_info,
            **context,
        },
    )
    if auth.renewed:
        set_auth_cookies(content, auth.renewed)
    return content


@router.get("/", response_class=HTMLResponse)
async def home_page(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    ui_service: UIService = Depends(get_ui_service),
):
    stats = await ui_service.get_home_page_data()
    return await _enforce_authentication(
        request,
        "index.html",
        {
            "active_page": "home",
            "stats": stats,
            "grafana_url": Config.GRAFANA_URL,
            "graylog_url": Config.GRAYLOG_URL,
            "pgadmin_url": Config.PGADMIN_URL,
        },
        auth_service,
        user_service,
    )


@router.get("/projects", response_class=HTMLResponse)
async def projects_page(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    ui_service: UIService = Depends(get_ui_service),
):
    projects = await ui_service.get_projects_page_data()
    return await _enforce_authentication(
        request,
        "projects.html",
        {
            "active_page": "projects",
            "projects": projects,
        },
        auth_service,
        user_service,
    )


@router.get("/connectors", response_class=HTMLResponse)
async def connectors_page(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    ui_service: UIService = Depends(get_ui_service),
):
    connectors = await ui_service.get_connectors_page_data()
    return await _enforce_authentication(
        request,
        "connectors.html",
        {
            "active_page": "connectors",
            "connectors": connectors,
            "last_updated_at": datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
        },
        auth_service,
        user_service,
    )


@router.get("/connectors/list")
async def connectors_list(
    request: Request,
    auth_service: AuthenticationService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    ui_service: UIService = Depends(get_ui_service),
):
    auth = await enforce_web_auth(request, auth_service, user_service)
    if auth.redirect:
        raise HTTPException(status_code=401, detail="Not authenticated")

    connectors = await ui_service.get_connectors_page_data()
    return [asdict(connector) for connector in connectors]
