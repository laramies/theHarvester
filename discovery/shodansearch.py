# Do 'sudo pip2 install shodan' to get the built-in module
import shodan
import sys

API_KEY = "oCiMsgM6rQWqiTvPxFHYcExlZgg7wvTt"

class search_shodan():

    def __init__(self, host):
        self.host = host
        self.api = shodan.Shodan(API_KEY)

    def run(self):
        try:
            result = self.api.search(self.host)
            for service in result['matches']:
                print ("%s:%s" % (service['ip_str'], service['port']))
            return result
        except:
            print "SHODAN empty reply or error in the call"
            return "error"
