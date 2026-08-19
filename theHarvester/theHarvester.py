import asyncio
import os
import sys
from collections.abc import Callable

from theHarvester import __main__
from theHarvester.lib.database import dispose_sqlite_databases

LoopFactory = Callable[[], asyncio.AbstractEventLoop]

# winloop cannot spawn subprocesses created with ``startupinfo``, which is how Playwright
# starts its driver, so sources such as Baidu and the screenshot module die with
# ``ValueError: startupinfo is not supported``. Standard asyncio on Windows handles them,
# so winloop stays opt-in behind this environment variable.
WINLOOP_ENV_VAR = 'THEHARVESTER_USE_WINLOOP'
_TRUTHY = frozenset({'1', 'true', 'yes', 'on'})


async def _run() -> None:
    try:
        await __main__.entry_point()
    finally:
        await dispose_sqlite_databases()


def _optional_loop_factory(module_name: str) -> LoopFactory | None:
    try:
        module = __import__(module_name)
    except ModuleNotFoundError:
        return None
    return module.new_event_loop


def main() -> None:
    platform = sys.platform
    loop_factory: LoopFactory | None = None  # asyncio's standard event loop
    if platform == 'win32':
        if os.environ.get(WINLOOP_ENV_VAR, '').strip().lower() in _TRUTHY:
            loop_factory = _optional_loop_factory('winloop')
    else:
        loop_factory = _optional_loop_factory('uvloop')
    asyncio.run(_run(), loop_factory=loop_factory)
