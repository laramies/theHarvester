# Note: This script runs theHarvester
# from platform import python_version
import sys
import asyncio
from theHarvester import __main__

if sys.version_info.major < 3 or sys.version_info.minor < 7:
    print('\033[93m[!] Make sure you have Python 3.7+ installed, quitting.\n\n \033[0m')
    sys.exit(1)

if __name__ == '__main__':
    platform = sys.platform
    if platform == 'win32':
        # Required or things will break if trying to take screenshots
        import multiprocessing

        multiprocessing.freeze_support()
        asyncio.DefaultEventLoopPolicy = asyncio.WindowsSelectorEventLoopPolicy
    else:
        # with uvloop 0.16.0 support for python3.10 has been added
        # https://github.com/MagicStack/uvloop/releases/tag/v0.16.0
        import uvloop

        uvloop.install()

        if "linux" in platform:
            import aiomultiprocess

            # As we are not using Windows we can change the spawn method to fork for greater performance
            aiomultiprocess.set_context("fork")
    asyncio.run(__main__.entry_point())
