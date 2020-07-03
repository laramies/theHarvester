### Welcome to theHarvester's REST API

There are a couple different ways to run the app

1. Python 
	Simply run restfulHarvest.py 
	
2. Docker Container
	Using the Dockerfile provided you could do
	docker build -t theharvesterapp .
	docker run --name mycontainer -p 80:80 -d -e ACCESS_LOG=/var/log/app.log -e LOG_LEVEL="debug" -e APP_MODULE="theHarvester.lib.app.api:app" theharvesterapp 


http://104.196.42.201/query?limit=300&domain=yale.edu&source=baidu,intelx,bing&filename=test

ImportError: Error loading shared library libgcc_s.so.1: No such file or directory (needed by /usr/local/lib/python3.7/sit
e-packages/orjson.cpython-37m-x86_64-linux-gnu.so)

notoriousrebel/theharvesterapp:v0.0.1