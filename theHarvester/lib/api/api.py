from __future__ import annotations

from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from theHarvester import __version__
from theHarvester.lib.api.harvestview import router as harvestview_router
from theHarvester.lib.api.runs import router as api_router
from theHarvester.lib.api.runtime import ApiRuntime, create_runtime
from theHarvester.lib.api.schedule_store import dispose_schedule_databases
from theHarvester.lib.api.schedules import router as schedule_router
from theHarvester.lib.database import dispose_sqlite_databases

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

type RuntimeFactory = Callable[[], ApiRuntime]


STATIC_DIRECTORY = Path(__file__).resolve().parent / 'static'


def create_app(*, runtime_factory: RuntimeFactory = create_runtime) -> FastAPI:
    """Build an API application with an explicitly injectable runtime graph."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        runtime = runtime_factory()
        application.state.runtime = runtime
        try:
            await runtime.start()
            yield
        finally:
            try:
                await runtime.stop()
            finally:
                try:
                    await dispose_schedule_databases()
                finally:
                    try:
                        await dispose_sqlite_databases()
                    finally:
                        application.state.runtime = None

    application = FastAPI(
        title='theHarvester API',
        description='Local API for finite theHarvester enumeration runs and run schedules',
        version=__version__,
        docs_url='/docs',
        redoc_url='/redoc',
        lifespan=lifespan,
    )
    application.include_router(harvestview_router)
    application.include_router(api_router)
    application.include_router(schedule_router)
    application.mount('/static', StaticFiles(directory=STATIC_DIRECTORY), name='static')
    return application


app = create_app()
