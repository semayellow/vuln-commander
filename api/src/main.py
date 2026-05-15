from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from api.src.core.routers import core_router


app = FastAPI()

app.mount("/static", StaticFiles(directory=f'{Path(__file__).parent}/static'), name="static")

app.include_router(core_router)
