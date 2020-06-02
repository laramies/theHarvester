#!/usr/bin/python3

import uvicorn
from theHarvester.lib.web import api

uvicorn.run(app=api.app)
