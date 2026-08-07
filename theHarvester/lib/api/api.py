from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.staticfiles import StaticFiles

from theHarvester import __version__
from theHarvester.lib.api.rate_limit import limiter
from theHarvester.lib.api.run_worker import start_worker, stop_worker
from theHarvester.lib.api.runs import router as api_router

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await start_worker()
    try:
        yield
    finally:
        await stop_worker()


app = FastAPI(
    title='theHarvester API',
    description='Local API for finite theHarvester enumeration runs',
    version=__version__,
    docs_url='/docs',
    redoc_url='/redoc',
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore
app.add_middleware(
    cast('Any', CORSMiddleware),
    allow_origins=[],
    allow_credentials=False,
    allow_methods=['GET', 'POST'],
    allow_headers=['Content-Type', 'X-API-Key'],
)
app.include_router(api_router)

try:
    app.mount('/static', StaticFiles(directory='theHarvester/lib/api/static/'), name='static')
except RuntimeError:
    static_path = os.path.expanduser('~/.local/share/theHarvester/static/')
    os.makedirs(static_path, exist_ok=True)
    app.mount('/static', StaticFiles(directory=static_path), name='static')
