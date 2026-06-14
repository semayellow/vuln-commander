from fastapi import APIRouter

from api.src.v1.user.routers.user_router import router as user_router
from api.src.v1.auth.routers.auth_routers import router as auth_router
from api.src.v1.project.routers.project_router import router as project_router
from api.src.v1.connector.routers.connector_router import router as connector_router
from api.src.v1.vuln.routers.vuln_router import router as vuln_router
from api.src.v1.ui.routers.ui_router import router as ui_router


core_router = APIRouter(prefix="/api/v1")
core_router.include_router(ui_router)
core_router.include_router(auth_router)
core_router.include_router(user_router)
core_router.include_router(project_router)
core_router.include_router(connector_router)
core_router.include_router(vuln_router)
