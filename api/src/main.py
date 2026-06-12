from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pathlib import Path

from api.src.core.routers import core_router


app = FastAPI()

app.mount("/static", StaticFiles(directory=f'{Path(__file__).parent}/static'), name="static")


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/api/v1/", status_code=302)


app.include_router(core_router)
