from discovery.shodan import Shodan
import sys
from discovery.constants import *

class search_shodan():

    def __init__(self, host):
        self.host = host
        self.key = sh
        if self.key == "":
            raise MissingKey(True)
        self.api = Shodan(self.key)
        
    def run(self):
        try:
            result = self.api.host(self.host)
            #for service in result['data']:
            #    print ("%s:%s" % (service['ip_str'], service['port']))
            #   print ("%s" % (service['product']))
            #    print ("%s" % (service['hostnames']))
            return result
        except Exception as e:
            print("SHODAN empty reply or error in the call")
            return "error"
