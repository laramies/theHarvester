import asyncio
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

    async def search_ip(self, ip) -> OrderedDict:
        try:
            ipaddress = ip
            # Run the synchronous Shodan API call in a thread pool to avoid
            # blocking the async event loop. The shodan library does not provide
            # native async support, so self.api.host() is a blocking HTTP call.
            results = await asyncio.to_thread(self.api.host, ipaddress)

            if not results or not isinstance(results, dict):
                print(f'Shodan: No data found for IP {ip}')
                return OrderedDict({ip: 'Not in Shodan'})

            if 'data' not in results or not results['data']:
                print(f'Shodan: No data found for IP {ip}')
                return OrderedDict({ip: 'Not in Shodan'})

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

            data_first_dict = results['data'][0] if isinstance(results['data'], list) and len(results['data']) > 0 else {}

            if isinstance(data_first_dict, dict):
                if 'ip_str' in data_first_dict:
                    ip_str += str(data_first_dict['ip_str'])

                if 'http' in data_first_dict and isinstance(data_first_dict['http'], dict):
                    http_results_dict = data_first_dict['http']
                    if 'title' in http_results_dict:
                        title_val = str(http_results_dict['title']).strip()
                        if title_val != 'None':
                            title += title_val
                    if 'components' in http_results_dict and isinstance(http_results_dict['components'], dict):
                        for key in http_results_dict['components'].keys():
                            technologies.append(key)
                    if 'server' in http_results_dict:
                        server_val = str(http_results_dict['server']).strip()
                        if server_val != 'None':
                            server += server_val

            for key, value in results.items():
                if key == 'asn':
                    if isinstance(value, str):
                        asn += value
                    elif value is not None:
                        asn += str(value)
                if key == 'domains':
                    if isinstance(value, list):
                        domain_values = [str(domain) for domain in value]
                        domain_values.sort()
                        domains.extend(domain_values)
                if key == 'hostnames':
                    if isinstance(value, list):
                        hostname_values = [str(host).strip() for host in value]
                        hostname_values.sort()
                        hostnames.extend(hostname_values)
                if key == 'isp':
                    if isinstance(value, str):
                        isp += value
                    elif value is not None:
                        isp += str(value)
                if key == 'org':
                    org += str(value)
                if key == 'ports':
                    if isinstance(value, list):
                        port_values = [int(port) for port in value if isinstance(port, int)]
                        port_values.sort()
                        ports.extend(port_values)
                if key == 'product':
                    if isinstance(value, str):
                        product += value
                    elif isinstance(value, list):
                        product += ', '.join(str(item) for item in value if item is not None)

            technologies = list(set(technologies))

            result = OrderedDict()
            result[ip] = {
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

            return result
        except exception.APIError as e:
            print(f'{ip}: Not in Shodan ({e})')
            return OrderedDict({ip: f'Not in Shodan: {e}'})
        except Exception as e:
            return OrderedDict({ip: f'Error occurred in the Shodan IP search module: {e}'})
