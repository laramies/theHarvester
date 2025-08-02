from collections import OrderedDict

from shodan import Shodan, exception

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core


class SearchShodan:
    def __init__(self) -> None:
        self.key = Core.shodan_key()
        if self.key is None:
            raise MissingKey('Shodan')
        self.api = Shodan(self.key)
        self.hostdatarow: list = []
        self.tracker: OrderedDict = OrderedDict()

    async def search_ip(self, ip) -> OrderedDict:
        try:
            ipaddress = ip
            results = self.api.host(ipaddress)
            
            if not results or 'data' not in results or not results['data']:
                print(f'Shodan: No data found for IP {ip}')
                return OrderedDict()
            asn = ''
            domains: list = list()
            hostnames: list = list()
            ip_str = ''
            isp = ''
            org = ''
            ports: list = list()
            title = ''
            server = ''
            product = ''
            technologies: list = list()

            data_first_dict = dict(results['data'][0])

            if 'ip_str' in data_first_dict:
                ip_str += data_first_dict['ip_str']

            if 'http' in data_first_dict:
                http_results_dict = dict(data_first_dict['http'])
                if 'title' in http_results_dict:
                    title_val = str(http_results_dict['title']).strip()
                    if title_val != 'None':
                        title += title_val
                if 'components' in http_results_dict:
                    for key in http_results_dict['components'].keys():
                        technologies.append(key)
                if 'server' in http_results_dict:
                    server_val = str(http_results_dict['server']).strip()
                    if server_val != 'None':
                        server += server_val

            for key, value in results.items():
                if key == 'asn':
                    asn += value
                if key == 'domains':
                    value = list(value)
                    value.sort()
                    domains.extend(value)
                if key == 'hostnames':
                    value = [host.strip() for host in list(value)]
                    value.sort()
                    hostnames.extend(value)
                if key == 'isp':
                    isp += value
                if key == 'org':
                    org += str(value)
                if key == 'ports':
                    value = list(value)
                    value.sort()
                    ports.extend(value)
                if key == 'product':
                    product += value

            technologies = list(set(technologies))

            self.tracker[ip] = {
                'asn': asn.strip(),
                'domains': domains,
                'hostnames': hostnames,
                'ip_str': ip_str.strip(),
                'isp': isp.strip(),
                'org': org.strip(),
                'ports': ports,
                'product': product.strip(),
                'server': server.strip(),
                'technologies': technologies,
                'title': title.strip(),
            }

            return self.tracker
        except exception.APIError:
            print(f'{ip}: Not in Shodan')
            self.tracker[ip] = 'Not in Shodan'
        except Exception as e:
            # print(f'Error occurred in the Shodan IP search module: {e}')
            self.tracker[ip] = f'Error occurred in the Shodan IP search module: {e}'
        finally:
            return self.tracker
