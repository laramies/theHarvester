from shodan import Shodan
from shodan import exception
#from discovery.shodan import Shodan
from discovery.constants import *


class search_shodan:

    def __init__(self):
        self.key = shodanAPI_key
        if self.key == "":
            raise MissingKey(True)
        self.api = Shodan(self.key)
        self.hostdatarow = []

    def search_ip(self, ip):
        try:
            ipaddress = ip
            results = self.api.host(ipaddress)
            technologies = []
            servicesports = []
            for result in results['data']:
                try:
                    for key in result['http']['components'].keys():
                        technologies.append(key)
                except KeyError as e:
                    pass
                port = str(result.get('port'))
                product = str(result.get('product'))
                servicesports.append(str(product)+':'+str(port))
            technologies = list(set(technologies))
            self.hostdatarow = [
                    str(results.get('ip_str')), str(results.get('hostnames')).strip('[]\''),
                    str(results.get('org')), str(servicesports).strip('[]\''),
                    str(technologies).strip('[]\'')]
        except exception.APIError:
            print(ipaddress+": Not in Shodan")
            self.hostdatarow = [ipaddress, "Not in Shodan", "Not in Shodan", "Not in Shodan", "Not in Shodan"]

        except Exception as e:
            print("Error occurred in the Shodan IP search module: " + str(e))
        finally:
            return self.hostdatarow