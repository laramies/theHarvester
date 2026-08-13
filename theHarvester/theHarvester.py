import asyncio
import sys

from theHarvester import __main__
from theHarvester.lib.database import dispose_sqlite_databases


async def _run() -> None:
    try:
        await __main__.entry_point()
    finally:
        await dispose_sqlite_databases()


def main():
    platform = sys.platform
    if platform == 'win32':
        # Required or things will break if trying to take screenshots
        import multiprocessing

        multiprocessing.freeze_support()
        try:
            # See if we have winloop as a performance enhancement on windows
            import winloop

            asyncio.DefaultEventLoopPolicy = winloop.EventLoopPolicy
        except ModuleNotFoundError:
            # Fallback to WindowsSelectorEventLoopPolicy if available, else keep default
            asyncio.DefaultEventLoopPolicy = getattr(asyncio, 'WindowsSelectorEventLoopPolicy', asyncio.DefaultEventLoopPolicy)
    else:
        import uvloop

        uvloop.install()
    asyncio.run(_run())
