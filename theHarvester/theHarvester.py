import asyncio
import sys

from theHarvester import __main__
from theHarvester.lib.database import dispose_sqlite_databases


async def _run() -> None:
    try:
        await __main__.entry_point()
    finally:
        await dispose_sqlite_databases()


def _screenshots_requested() -> bool:
    return any(argument == '--screenshot' or argument.startswith('--screenshot=') for argument in sys.argv[1:])


def main() -> None:
    loop_factory = None  # asyncio's standard event loop
    if sys.platform == 'win32':
        if not _screenshots_requested():
            try:
                import winloop

                loop_factory = winloop.new_event_loop
            except ModuleNotFoundError:
                pass
    else:
        try:
            import uvloop

            loop_factory = uvloop.new_event_loop
        except ModuleNotFoundError:
            pass
    asyncio.run(_run(), loop_factory=loop_factory)
