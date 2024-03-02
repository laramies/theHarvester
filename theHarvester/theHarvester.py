import asyncio
import sys

from theHarvester import __main__


def main():
    platform = sys.platform
    if platform == 'win32':
        # Required or things will break if trying to take screenshots
        import multiprocessing

        multiprocessing.freeze_support()
        asyncio.DefaultEventLoopPolicy = asyncio.WindowsSelectorEventLoopPolicy
    else:
        import uvloop

        uvloop.install()

        if 'linux' in platform:
            import aiomultiprocess

            # As we are not using Windows, we can change the spawn method to fork for greater performance
            aiomultiprocess.set_context('fork')
    asyncio.run(__main__.entry_point())
