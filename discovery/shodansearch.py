from discovery.shodan import Shodan
import sys
from discovery.constants import *


class search_shodan():

    def __init__(self, ip):
        self.ip = ip
        self.key = shodanAPI_key
        if self.key == "":
            raise MissingKey(True)
        self.api = Shodan(self.key)
        self.hostdatarow = []
        
    def search_host(self):
        try:
            results = self.api.host(self.ip)
            for result in results['data']:
                technologies = []
                if ('components' in result) and ('http' in result): #not always getting "http" key in the response
                    for key in result['http']['components'].keys():
                        technologies.append(key)
                else:
                    technologies.append("None")
                if 'product' not in result: #not always getting "product" key in the response
                    product = 'None'
                else:
                    product = str(result['product'])
                if 'tags' not in result: #not always getting "tags": key in the response
                    tags = 'None'
                else:
                    tags = str(result['tags']).strip('[]')
                self.hostdatarow = [str(result['ip_str']), str(result['hostnames']).strip('[]'), str(result['location']['country_name']),
                            str(result['location']['city']), str(result['org']), str(result['isp']), str(result['asn']),
                            str(result['port']), str(result['os']), product, str(technologies).strip('[]'), tags]
        except Exception as e:
            print("Error occurred in the Shodan host search module: " + str(e))
        finally:
            return self.hostdatarow
