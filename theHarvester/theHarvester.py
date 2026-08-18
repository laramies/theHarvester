import asyncio
import sys

from theHarvester import __main__
from theHarvester.lib.database import dispose_sqlite_databases


async def _run() -> None:
    try:
        await __main__.entry_point()
    finally:
        await dispose_sqlite_databases()


def main() -> None:
    loop_factory = None  # asyncio's standard event loop
    if sys.platform != 'win32':
        try:
            import uvloop

            loop_factory = uvloop.new_event_loop
        except ModuleNotFoundError:
            pass
    asyncio.run(_run(), loop_factory=loop_factory)
