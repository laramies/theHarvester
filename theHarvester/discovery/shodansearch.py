import asyncio
import logging
import socket
from collections import OrderedDict
from datetime import UTC, datetime
from ipaddress import ip_address

import aiodns

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostchecker import resolve_ip_addresses
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)

HostResult = dict[str, object]


class SearchShodan:
    """Collect Shodan host data and retain ``asn`` + ``org`` attribution.

    Shodan documents ``org`` and ``isp`` as separate Host API fields. The
    organization attribution uses ``org`` and stays linked to the queried IP;
    ``isp`` remains ordinary Shodan output and is not treated as equivalent.
    """

    API_BASE_URL = 'https://api.shodan.io/shodan/host'
    # Preserve the official SDK's one-request-per-second pacing without retaining its blocking transport.
    REQUEST_INTERVAL_SECONDS = 1.0
    REQUEST_TIMEOUT_SECONDS: int | None = None

    def __init__(self, word: str | None = None) -> None:
        self.word = word.strip().lower().rstrip('.') if word is not None else None
        self.scope = self.word.removeprefix('www.') if self.word is not None else None
        self.key = Core.shodan_key()
        if self.key is None:
            raise MissingKey('Shodan')
        self.tracker: OrderedDict[str, HostResult | str] = OrderedDict()
        self.error_type: str | None = None
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.totalhosts: set[str] = set()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None
        self._next_request_at = 0.0

    async def _fetch_host(self, ip: str, proxy: bool) -> FetcherResponse:
        loop = asyncio.get_running_loop()
        delay = self._next_request_at - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        self._next_request_at = loop.time() + self.REQUEST_INTERVAL_SECONDS
        return await AsyncFetcher.fetch_json(
            f'{self.API_BASE_URL}/{ip}',
            params={'key': self.key},
            proxy=proxy,
            request_timeout=self.REQUEST_TIMEOUT_SECONDS,
        )

    def _record_host(self, ip: str, results: dict[str, object]) -> None:
        data = results.get('data')
        if data == []:
            logger.info(f'Shodan: No data found for IP {ip}')
            return
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            raise ValueError('invalid Shodan host response')

        data_first = data[0]
        http = data_first.get('http')
        http_data = http if isinstance(http, dict) else {}
        components = http_data.get('components')
        technology_values = components if isinstance(components, dict) else {}

        domains = results.get('domains')
        domain_values = sorted(str(domain) for domain in domains) if isinstance(domains, list) else []
        hostnames = results.get('hostnames')
        hostname_values = sorted(str(host).strip() for host in hostnames) if isinstance(hostnames, list) else []
        ports = results.get('ports')
        port_values = sorted(port for port in ports if isinstance(port, int)) if isinstance(ports, list) else []
        product_value = results.get('product')
        if isinstance(product_value, list):
            product = ', '.join(str(item) for item in product_value if item is not None)
        else:
            product = str(product_value) if product_value is not None else ''

        def normalized_string(value: object) -> str:
            return '' if value is None or str(value).strip() == 'None' else str(value).strip()

        asn = normalized_string(results.get('asn'))
        organization = normalized_string(results.get('org'))
        self.tracker[ip] = {
            'asn': asn,
            'domains': domain_values,
            'hostnames': hostname_values,
            'ip_str': normalized_string(results.get('ip_str') or data_first.get('ip_str')),
            'isp': normalized_string(results.get('isp')),
            'org': organization,
            'ports': port_values,
            'product': product,
            'server': normalized_string(http_data.get('server')),
            'technologies': sorted(str(name) for name in technology_values),
            'title': normalized_string(http_data.get('title')),
        }

        if asn and organization:
            self.asn_attributions.add(
                AsnAttributionObservation(
                    'action',
                    'shodan',
                    asn,
                    organization,
                    'ip',
                    ip,
                    datetime.now(UTC),
                )
            )

    async def search_ip(self, ip: str, *, proxy: bool = False) -> OrderedDict[str, HostResult | str]:
        self.error_type = None
        try:
            normalized_ip = str(ip_address(ip.strip()))
        except ValueError:
            self.error_type = 'ValueError'
            self.tracker[ip] = 'Shodan request failed'
            return self.tracker

        try:
            response = await self._fetch_host(normalized_ip, proxy)
            if response.status == 404:
                logger.info(f'{normalized_ip}: Not in Shodan')
                self.tracker[normalized_ip] = 'Not in Shodan'
                return self.tracker
            if not 200 <= response.status < 300:
                self.error_type = f'HTTP{response.status}Error'
                self.tracker[normalized_ip] = 'Shodan request failed'
                return self.tracker
            if not isinstance(response.body, dict):
                self.error_type = 'InvalidResponseError'
                self.tracker[normalized_ip] = 'Shodan request failed'
                return self.tracker
            try:
                self._record_host(normalized_ip, response.body)
            except (TypeError, ValueError):
                self.error_type = 'InvalidResponseError'
                self.tracker[normalized_ip] = 'Shodan request failed'
        except ResponseStreamError as error:
            self.error_type = {
                'invalid-response': 'InvalidResponseError',
                'response-limit': 'ResponseLimitError',
                'transport-error': 'TransportError',
            }[error.reason]
            self.tracker[normalized_ip] = 'Shodan request failed'
        except Exception as error:
            self.error_type = type(error).__name__
            self.tracker[normalized_ip] = 'Shodan request failed'
        return self.tracker

    async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
        return self.asn_attributions

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        if self.word is None:
            raise ValueError('A discovery target is required')
        assert self.scope is not None

        self.totalhosts.clear()
        self.execution_status = None
        self.stop_reason = None
        try:
            resolved_ips = await resolve_ip_addresses(self.word, family=socket.AF_INET)
            if not resolved_ips:
                raise ValueError('target has no IPv4 addresses')
        except TimeoutError:
            self.execution_status = 'failed'
            self.stop_reason = 'dns-timeout'
            return
        except aiodns.error.DNSError as error:
            self.execution_status = 'failed'
            self.stop_reason = (
                'dns-timeout' if error.args and error.args[0] == aiodns.error.ARES_ETIMEOUT else 'dns-resolution-failed'
            )
            return
        except ValueError:
            self.execution_status = 'failed'
            self.stop_reason = 'dns-resolution-failed'
            return

        provider_error_types: set[str] = set()
        for resolved_ip in resolved_ips:
            result = await self.search_ip(resolved_ip, proxy=proxy)
            if self.error_type is not None:
                provider_error_types.add(self.error_type)
                continue

            host_data = result.get(resolved_ip)
            if isinstance(host_data, dict):
                hostnames = host_data.get('hostnames')
                if not isinstance(hostnames, list):
                    continue
                for hostname in hostnames:
                    normalized = normalize_scoped_hostname(hostname, self.scope)
                    if normalized and normalized != self.scope:
                        self.totalhosts.add(normalized)

        self.error_type = next(iter(sorted(provider_error_types)), None)
        if provider_error_types:
            self.execution_status = 'partial' if self.totalhosts else 'failed'
            if provider_error_types <= {'HTTP401Error', 'HTTP403Error'}:
                self.stop_reason = 'access-denied'
            elif provider_error_types == {'HTTP429Error'}:
                self.stop_reason = 'rate-limited'
            elif len(resolved_ips) == 1:
                self.stop_reason = 'provider-error'
            else:
                self.stop_reason = 'provider-errors'
            return

        self.execution_status = 'completed'
        self.stop_reason = None if self.totalhosts else 'no-results'
