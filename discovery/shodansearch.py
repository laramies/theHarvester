from shodan import WebAPI
import sys


class search_shodan():

    def __init__(self, host):
        self.host = host
        self.key = "oCiMsgM6rQWqiTvPxFHYcExlZgg7wvTt"
        if self.key == "":
            print "You need an API key in order to use SHODAN database. You can get one here: http://www.shodanhq.com/"
            sys.exit()
        self.api = WebAPI(self.key)

    def run(self):
        try:
            host = self.api.host(self.host)
            return host['data']
        except:
            print "SHODAN empty reply or error in the call"
            return "error"
