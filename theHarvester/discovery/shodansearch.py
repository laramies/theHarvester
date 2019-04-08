from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from shodan import exception
from shodan import Shodan


class SearchShodan:

    def __init__(self):
        self.key = Core.shodan_key()
        if self.key is None:
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
                except KeyError:
                    pass
                port = str(result.get('port'))
                product = str(result.get('product'))
                servicesports.append(str(product)+':'+str(port))
            technologies = list(set(technologies))
            self.hostdatarow = [
                    str(results.get('ip_str')), str(results.get('hostnames')).strip('[]\''),
                    str(results.get('org')), str(servicesports).replace('\'', '').strip('[]'),
                    str(technologies).replace('\'', '').strip('[]')]
        except exception.APIError:
            print(f'{ipaddress}: Not in Shodan')
            self.hostdatarow = [ipaddress, "Not in Shodan", "Not in Shodan", "Not in Shodan", "Not in Shodan"]

        except Exception as e:
            print(f'Error occurred in the Shodan IP search module: {e}')
        finally:
            return self.hostdatarow
