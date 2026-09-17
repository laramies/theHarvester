import logging
from ipaddress import ip_address
from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus

logger = logging.getLogger(__name__)


class SearchFullHunt:
    """Search the FullHunt API for domain and host data.

    FullHunt provides endpoints for domain details, subdomains, host details,
    and its data-intelligence search.

    """

    BASE_URL = 'https://fullhunt.io/api/v1'

    def __init__(self, word) -> None:
        self.word = word
        try:
            self.key = Core.fullhunt_key()
        except Exception as error:
            raise MissingKey('fullhunt') from error
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('fullhunt')
        self.total_results: dict[str, Any] = {
            'hosts': [],  # List of subdomains
            'ips': [],  # List of IP addresses
            'ports': set(),  # Set of open ports
            'technologies': [],  # List of technologies found
            'tags': [],  # List of tags
            'domain_details': {},  # Full domain details response
            'host_details': [],  # List of host details
            'dns_records': {},  # DNS records for the domain
            'http_info': {},  # HTTP information (titles, status codes)
            'geo_info': {},  # Geographic information
            'cloud_info': {},  # Cloud provider information
            'cert_info': [],  # Certificate information
        }
        self.proxy = False
        self._report: SourceExecutionReport | None = None

    def _stop(self, status: SourceReportStatus, reason: str) -> None:
        self._report = SourceExecutionReport(status, reason)

    def _get_headers(self) -> dict[str, str]:
        """Return headers for FullHunt API requests."""
        return {'User-Agent': Core.get_user_agent(), 'X-API-KEY': self.key}

    async def _fetch_data(self, endpoint: str, session: Any | None = None) -> dict[str, Any]:
        """Fetch JSON data from one FullHunt endpoint."""
        url = f'{self.BASE_URL}/{endpoint}'
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            headers=self._get_headers(),
            proxy=self.proxy if session is None else False,
            include_metadata=True,
            session=session,
        )
        metadata = response[0] if response else None
        if error := provider_http_error(metadata):
            self._stop(*error)
            raise RuntimeError(f'FullHunt request failed: {error[1]}')
        assert isinstance(metadata, FetcherResponse)
        if not isinstance(metadata.body, dict):
            self._stop('failed', 'invalid-response')
            raise ValueError('FullHunt returned malformed data')
        return metadata.body

    async def get_domain_details(self, session: Any | None = None) -> dict[str, Any]:
        """Return FullHunt details for the target domain."""
        endpoint = f'domain/{self.word}/details'
        return await self._fetch_data(endpoint, session)

    async def get_subdomains(self, session: Any | None = None) -> dict[str, Any]:
        """Return subdomains for the target domain."""
        endpoint = f'domain/{self.word}/subdomains'
        return await self._fetch_data(endpoint, session)

    async def get_host_details(self, host: str) -> dict[str, Any]:
        """Return FullHunt details for one host."""
        endpoint = f'host?host={host}'
        return await self._fetch_data(endpoint)

    async def extract_data_from_domain_details(self, details: dict[str, Any]) -> None:
        """Collect normalized results from a domain-details response."""
        if 'hosts' not in details:
            return

        hosts = details['hosts']
        for host_data in hosts:
            if not isinstance(host_data, dict):
                self._stop('failed', 'invalid-response')
                logger.info('FullHunt ignored a malformed host item')
                continue
            hostname = normalize_scoped_hostname(host_data.get('host'), self.word)
            address = host_data.get('ip_address')
            try:
                normalized_address = str(ip_address(address)) if isinstance(address, str) else None
            except ValueError:
                normalized_address = None
            if (
                hostname is None
                or (address is not None and normalized_address is None)
                or (
                    'network_ports' in host_data
                    and (
                        not isinstance(host_data['network_ports'], (list, set, tuple))
                        or any(
                            not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535
                            for port in host_data['network_ports']
                        )
                    )
                )
                or any(
                    field in host_data
                    and (not isinstance(host_data[field], list) or any(not isinstance(value, str) for value in host_data[field]))
                    for field in ('products', 'tags')
                )
                or any(
                    field in host_data and not isinstance(host_data[field], dict)
                    for field in ('dns_records', 'http_response', 'geo', 'cloud', 'certificate')
                )
            ):
                self._stop('failed', 'invalid-response')
                logger.info('FullHunt ignored a malformed host item')
                continue
            # Extract subdomains
            self.total_results['hosts'].append(hostname)

            # Extract IPs
            if normalized_address:
                self.total_results['ips'].append(normalized_address)

            # Extract ports
            if host_data.get('network_ports'):
                self.total_results['ports'].update(host_data['network_ports'])

            # Extract technologies/products
            if host_data.get('products'):
                self.total_results['technologies'].extend(host_data['products'])

            # Extract tags
            if host_data.get('tags'):
                self.total_results['tags'].extend(host_data['tags'])

            # Extract DNS information
            if 'dns_records' in host_data:
                dns_records = host_data['dns_records']

                if hostname not in self.total_results['dns_records']:
                    self.total_results['dns_records'][hostname] = {}

                for record_type, records in dns_records.items():
                    self.total_results['dns_records'][hostname][record_type] = records

            # Extract HTTP information
            if 'http_response' in host_data:
                http_info = host_data['http_response']

                if hostname not in self.total_results['http_info']:
                    self.total_results['http_info'][hostname] = {}

                for key, value in http_info.items():
                    self.total_results['http_info'][hostname][key] = value

            # Extract geographic information
            if 'geo' in host_data:
                geo_info = host_data['geo']

                if hostname not in self.total_results['geo_info']:
                    self.total_results['geo_info'][hostname] = {}

                for key, value in geo_info.items():
                    self.total_results['geo_info'][hostname][key] = value

            # Extract cloud information
            if 'cloud' in host_data:
                cloud_info = host_data['cloud']

                if hostname not in self.total_results['cloud_info']:
                    self.total_results['cloud_info'][hostname] = {}

                for key, value in cloud_info.items():
                    self.total_results['cloud_info'][hostname][key] = value

            # Extract certificate information
            if 'certificate' in host_data:
                cert_info = {**host_data['certificate'], 'hostname': hostname}
                self.total_results['cert_info'].append(cert_info)

        # Deduplicate results
        self.total_results['hosts'] = list(set(self.total_results['hosts']))
        self.total_results['ips'] = list(set(self.total_results['ips']))
        self.total_results['technologies'] = list(set(self.total_results['technologies']))
        self.total_results['tags'] = list(set(self.total_results['tags']))

    async def do_search(self) -> None:
        """Query the FullHunt endpoints used by this source."""
        try:
            async with AsyncFetcher.open_session(
                headers=self._get_headers(),
                proxy=self.proxy,
                request_timeout=60,
            ) as session:
                # First get domain details which includes most information
                domain_details = await self.get_domain_details(session)
                if not isinstance(domain_details.get('hosts'), list):
                    raise ValueError('FullHunt returned malformed domain details')
                self.total_results['domain_details'] = domain_details
                await self.extract_data_from_domain_details(domain_details)

                # If no hosts found in domain details, try the dedicated subdomains endpoint
                if not self.total_results['hosts']:
                    subdomains_response = await self.get_subdomains(session)
                    hosts = subdomains_response.get('hosts')
                    if not isinstance(hosts, list):
                        raise ValueError('FullHunt returned malformed subdomains')
                    for host in hosts:
                        if normalized_host := normalize_scoped_hostname(host, self.word):
                            self.total_results['hosts'].append(normalized_host)
                        else:
                            self._stop('failed', 'invalid-response')
                            logger.info('FullHunt ignored a malformed subdomain item')

        except Exception as error:
            if self._report is None:
                reason = 'invalid-response' if isinstance(error, ValueError) else 'transport-error'
                self._stop('failed', reason)
            logger.info('Error during FullHunt search: %s', type(error).__name__)
            return

    async def get_hostnames(self) -> list[str]:
        """Return discovered subdomains."""
        return self.total_results['hosts']

    async def get_ips(self) -> list[str]:
        """Return discovered IP addresses."""
        return self.total_results['ips']

    async def get_ports(self) -> list[int]:
        """Return open ports."""
        return list(self.total_results['ports'])

    async def get_technologies(self) -> list[str]:
        """Return detected technologies."""
        return self.total_results['technologies']

    async def get_tags(self) -> list[str]:
        """Return FullHunt tags."""
        return self.total_results['tags']

    async def get_dns_records(self) -> dict[str, dict[str, list[str]]]:
        """Return DNS records for hosts."""
        return self.total_results['dns_records']

    async def get_http_info(self) -> dict[str, dict[str, Any]]:
        """Return HTTP information for hosts."""
        return self.total_results['http_info']

    async def get_geo_info(self) -> dict[str, dict[str, Any]]:
        """Return geographic information for hosts."""
        return self.total_results['geo_info']

    async def get_cloud_info(self) -> dict[str, dict[str, Any]]:
        """Return cloud-provider information for hosts."""
        return self.total_results['cloud_info']

    async def get_certificate_info(self) -> list[dict[str, Any]]:
        """Return certificate information for hosts."""
        return self.total_results['cert_info']

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        """Run the FullHunt search.

        Args:
            proxy: Whether to use a proxy for requests.

        """
        self.proxy = proxy
        self._report = None
        await self.do_search()
        return self._report
