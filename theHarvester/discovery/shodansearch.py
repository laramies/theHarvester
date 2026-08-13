import asyncio
import logging
import socket
from collections import OrderedDict
from datetime import UTC, datetime
from functools import partial
from ipaddress import ip_address

import aiodns
from shodan import Shodan, exception

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.core import Core
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchShodan:
    """Collect Shodan host data and retain ``asn`` + ``org`` attribution.

    Shodan documents ``org`` and ``isp`` as separate Host API fields. The
    organization attribution uses ``org`` and stays linked to the queried IP;
    ``isp`` remains ordinary Shodan output and is not treated as equivalent.
    """

    REQUEST_TIMEOUT_SECONDS = 30
    AWAIT_TIMEOUT_SECONDS = REQUEST_TIMEOUT_SECONDS + 5

    def __init__(self, word: str | None = None) -> None:
        self.word = word.strip().lower().rstrip('.') if word is not None else None
        self.scope = self.word.removeprefix('www.') if self.word is not None else None
        self.key = Core.shodan_key()
        if self.key is None:
            raise MissingKey('Shodan')
        self.api = Shodan(self.key)
        session = getattr(self.api, '_session', None)
        if session is not None:
            session.request = partial(session.request, timeout=self.REQUEST_TIMEOUT_SECONDS)
        self.hostdatarow: list = []
        self.tracker: OrderedDict = OrderedDict()
        self.error_type: str | None = None
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.totalhosts: set[str] = set()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def search_ip(self, ip) -> OrderedDict:
        self.error_type = None
        try:
            ipaddress = ip
            async with asyncio.timeout(self.AWAIT_TIMEOUT_SECONDS):
                results = await asyncio.to_thread(self.api.host, ipaddress)

            if not results or 'data' not in results or not results['data']:
                logger.info(f'Shodan: No data found for IP {ip}')
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
            organization_label = results.get('org')
            if asn.strip() and isinstance(organization_label, str) and organization_label.strip():
                try:
                    subject_ip = str(ip_address(str(ip).strip()))
                    self.asn_attributions.add(
                        AsnAttributionObservation(
                            'action',
                            'shodan',
                            asn,
                            organization_label,
                            'ip',
                            subject_ip,
                            datetime.now(UTC),
                        )
                    )
                except ValueError:
                    logger.info('Shodan returned invalid ASN organization attribution')

            return self.tracker
        except exception.APIError as error:
            if str(error).strip().rstrip('.').casefold() == 'no information available for that ip':
                logger.info(f'{ip}: Not in Shodan')
                self.tracker[ip] = 'Not in Shodan'
            else:
                self.error_type = type(error).__name__
                self.tracker[ip] = 'Shodan request failed'
        except Exception as e:
            self.error_type = type(e).__name__
            self.tracker[ip] = 'Shodan request failed'

        return self.tracker

    async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
        return self.asn_attributions

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        del proxy  # The Shodan SDK owns its transport configuration.
        if self.word is None:
            raise ValueError('A discovery target is required')
        assert self.scope is not None

        self.totalhosts.clear()
        self.execution_status = None
        self.stop_reason = None
        try:
            resolver = aiodns.DNSResolver(timeout=self.REQUEST_TIMEOUT_SECONDS)
            async with asyncio.timeout(self.AWAIT_TIMEOUT_SECONDS):
                answer = await resolver.getaddrinfo(self.word, family=socket.AF_INET)
            resolved_ip = answer.nodes[0].addr[0]
            resolved_ip = str(ip_address(resolved_ip))
        except TimeoutError:
            self.execution_status = 'failed'
            self.stop_reason = 'dns-timeout'
            return
        except (aiodns.error.DNSError, IndexError, ValueError):
            self.execution_status = 'failed'
            self.stop_reason = 'dns-resolution-failed'
            return

        result = await self.search_ip(resolved_ip)
        if self.error_type is not None:
            self.execution_status = 'failed'
            self.stop_reason = 'provider-timeout' if self.error_type == 'TimeoutError' else 'provider-error'
            return

        host_data = result.get(resolved_ip)
        if isinstance(host_data, dict):
            for hostname in host_data.get('hostnames', []):
                normalized = normalize_scoped_hostname(hostname, self.scope)
                if normalized and normalized != self.scope:
                    self.totalhosts.add(normalized)

        self.execution_status = 'completed'
        self.stop_reason = None if self.totalhosts else 'no-results'
