from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from theHarvester import __version__
from theHarvester.lib.api.harvestview import router as harvestview_router
from theHarvester.lib.api.run_worker import start_worker, stop_worker
from theHarvester.lib.api.runs import router as api_router
from theHarvester.lib.api.schedule_service import start_scheduler, stop_scheduler
from theHarvester.lib.api.schedules import router as schedule_router
from theHarvester.lib.database import dispose_sqlite_databases

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await start_worker()
    try:
        await start_scheduler()
        try:
            yield
        finally:
            await stop_scheduler()
    finally:
        try:
            await stop_worker()
        finally:
            await dispose_sqlite_databases()


app = FastAPI(
    title='theHarvester API',
    description='Local API for finite theHarvester enumeration runs and run schedules',
    version=__version__,
    docs_url='/docs',
    redoc_url='/redoc',
    lifespan=lifespan,
)
app.include_router(harvestview_router)
app.include_router(api_router)
app.include_router(schedule_router)
STATIC_DIRECTORY = Path(__file__).resolve().parent / 'static'
app.mount('/static', StaticFiles(directory=STATIC_DIRECTORY), name='static')
