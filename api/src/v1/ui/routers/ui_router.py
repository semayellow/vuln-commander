from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from api.src.core.utils.config import Config

router = APIRouter()
templates_path = Path(__file__).parent.parent.parent.parent
templates = Jinja2Templates(directory=f"{templates_path}/templates")


@router.get(
    "/",
    response_class=HTMLResponse,
)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "grafana_url": Config.GRAFANA_URL,
            "graylog_url": Config.GRAYLOG_URL,
            "pgadmin_url": Config.PGADMIN_URL,
        },
    )
