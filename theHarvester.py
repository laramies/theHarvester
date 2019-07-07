#!/usr/bin/env python3

# Note: This script runs theHarvester
from platform import python_version
import sys
if python_version()[0:3] < '3.6':
    print('\033[93m[!] Make sure you have Python 3.6+ installed, quitting.\n\n \033[0m')
    sys.exit(1)

from theHarvester import __main__
__main__.entry_point()
