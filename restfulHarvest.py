#!/usr/bin/env python3
import uvicorn
import theHarvester.lib.web.api as api
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-H', '--host', default='127.0.0.1', help='IP address to listen on default is 127.0.0.1')
parser.add_argument('-p', '--port', default=5000, help='Port to bind the web server to, default is 5000')
parser.add_argument('-l', '--log-level', default='info',
                    help='Set logging level, default is info but [critical|error|warning|info|debug|trace] can be set')
parser.add_argument('-r', '--reload', default=False, help='Enable auto-reload.', action='store_true')

args = parser.parse_args()

if __name__ == "__main__":
    uvicorn.run(app=api.app, host=args.host, port=args.port, log_level=args.log_level, reload=args.reload)
