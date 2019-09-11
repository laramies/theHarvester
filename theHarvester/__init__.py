from gevent import monkey as curious_george
curious_george.patch_all(thread=False, select=False)
