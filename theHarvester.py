#!/usr/bin/env python3

# Note: This script runs theHarvester
from platform import python_version
import sys
import asyncio

if python_version()[0:3] < '3.7':
    print('\033[93m[!] Make sure you have Python 3.7+ installed, quitting.\n\n \033[0m')
    sys.exit(1)

from theHarvester import __main__

if sys.platform == 'win32':
    asyncio.DefaultEventLoopPolicy = asyncio.WindowsSelectorEventLoopPolicy
else:
    import uvloop
    uvloop.install()

asyncio.run(__main__.entry_point())
