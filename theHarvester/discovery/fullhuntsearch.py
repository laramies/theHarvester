import logging
from ipaddress import ip_address
from typing import Any, ClassVar
from urllib.parse import quote

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

    Supported search filters (with examples):

    General filters:
    - domain: required domain, for example ``domain:kaspersky.com``
    - ip: asset IP address, for example ``ip:8.8.8.8``
    - tech: detected technology, for example ``tech:drupal``
    - host: specific host, for example ``host:ecommerce.kaspersky.com``
    - subdomain: subdomain, for example ``subdomain:video.kaspersky.com``
    - tld: top-level domain, for example ``tld:com``
    - tag: tag, for example ``tag:cdn``
    - is_dos_defense: DDoS protection flag, for example ``is_dos_defense:true``

    Network filters:
    - port: network port, for example ``port:80``
    - has_private_ip: private-IP flag, for example ``has_private_ip:true``
    - has_ipv6: IPv6 flag, for example ``has_ipv6:true``
    - is_live: live-asset flag, for example ``is_live:true``
    - is_resolvable: resolvable-asset flag, for example ``is_resolvable:true``
    - dns_a, dns_aaaa, dns_cname, dns_mx, dns_txt, dns_ptr, dns_ns: DNS records

    HTTP filters:
    - http_title: page title, for example ``http_title:Nginx``
    - http_status_code: status code, for example ``http_status_code:302``
    - http_favicon_hash: favicon hash, for example ``http_favicon_hash:9888t96t6ctsdgc9gc``

    Geographic filters:
    - country_code/country: country code, for example ``country_code:us``
    - city: city, for example ``city:ashburn``
    - asn: autonomous system number, for example ``asn:123124``

    Cloud filters:
    - is_cloud: cloud-hosted flag, for example ``is_cloud:true``
    - cloud_provider: provider, for example ``cloud_provider:Linode``
    - cloud_region: region, for example ``cloud_region:us-ca``

    Technology filters:
    - product: detected product, for example ``product:wordpress``
    - service: detected service, for example ``service:http``

    Certificate filters:
    - cert_issuer_common_name, cert_issuer_organization, cert_issuer_country
    - cert_issuer_serial_number, cert_signature_algorithm
    - cert_subject_common_name, cert_subject_country, cert_subject_province
    - cert_subject_locality, cert_subject_organization
    - cert_md5_fingerprint, cert_sha1_fingerprint
    """

    BASE_URL = 'https://fullhunt.io/api/v1'
    SEARCH_URL = 'https://fullhunt.io/api/v1/search'

    # Filter categories for easier organization
    GENERAL_FILTERS: ClassVar[list[str]] = ['domain', 'ip', 'tech', 'host', 'subdomain', 'tld', 'tag', 'is_dos_defense']

    NETWORK_FILTERS: ClassVar[list[str]] = [
        'port',
        'has_private_ip',
        'has_ipv6',
        'is_live',
        'is_resolvable',
        'dns_a',
        'dns_aaaa',
        'dns_cname',
        'dns_mx',
        'dns_txt',
        'dns_ptr',
        'dns_ns',
    ]

    HTTP_FILTERS: ClassVar[list[str]] = ['http_title', 'http_status_code', 'http_favicon_hash']

    GEO_FILTERS: ClassVar[list[str]] = ['country_code', 'country', 'city', 'asn']

    CLOUD_FILTERS: ClassVar[list[str]] = ['is_cloud', 'cloud_provider', 'cloud_region']

    TECH_FILTERS: ClassVar[list[str]] = ['product', 'service']

    CERT_FILTERS: ClassVar[list[str]] = [
        'cert_issuer_common_name',
        'cert_issuer_organization',
        'cert_issuer_country',
        'cert_issuer_serial_number',
        'cert_signature_algorithm',
        'cert_subject_common_name',
        'cert_subject_country',
        'cert_subject_province',
        'cert_subject_locality',
        'cert_subject_organization',
        'cert_md5_fingerprint',
        'cert_sha1_fingerprint',
    ]

    # Combine all filters for validation
    ALL_FILTERS: ClassVar[list[str]] = (
        GENERAL_FILTERS + NETWORK_FILTERS + HTTP_FILTERS + GEO_FILTERS + CLOUD_FILTERS + TECH_FILTERS + CERT_FILTERS
    )

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
            'search_results': [],  # Raw search results from advanced queries
        }
        self.proxy = False
        self.filters: dict[str, str] = {}  # Store filters for advanced searches
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

    def add_filter(self, filter_name: str, filter_value: str) -> None:
        """Add a filter for data-intelligence searches.

        Args:
            filter_name: Name from the supported filter list.
            filter_value: Filter value.

        Raises:
            ValueError: If the filter name is unsupported.

        """
        if filter_name not in self.ALL_FILTERS:
            valid_filters = ', '.join(self.ALL_FILTERS)
            raise ValueError(f'Invalid filter name: {filter_name}. Valid filters: {valid_filters}')

        self.filters[filter_name] = filter_value

    def add_filters(self, filters: dict[str, str]) -> None:
        """Add several data-intelligence search filters.

        Args:
            filters: Mapping of filter names to values.

        Raises:
            ValueError: If any filter name is unsupported.

        """
        for name, value in filters.items():
            self.add_filter(name, value)

    def clear_filters(self) -> None:
        """Clear all search filters."""
        self.filters = {}

    def _build_query_string(self) -> str:
        """Build a query string from the current filters."""
        # Start with the domain filter which is required
        query_parts = [f'domain:{self.word}']

        # Add all other filters
        for filter_name, filter_value in self.filters.items():
            # Skip domain filter as it's already added
            if filter_name == 'domain':
                continue

            query_parts.append(f'{filter_name}:{filter_value}')

        return ' '.join(query_parts)

    async def advanced_search(self, session: Any | None = None) -> dict[str, Any]:
        """Search the data-intelligence endpoint with the configured filters.

        Configure filters with ``add_filter`` or ``add_filters`` first.

        Returns:
            The search response.

        """
        query = self._build_query_string()
        encoded_query = quote(query)
        endpoint = f'search?query={encoded_query}'
        return await self._fetch_data(endpoint, session)

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

    async def search_tech(self, tech_name: str) -> dict[str, Any]:
        """Search for hosts using a technology."""
        self.add_filter('tech', tech_name)
        return await self.advanced_search()

    async def search_service(self, service_name: str) -> dict[str, Any]:
        """Search for hosts running a service."""
        self.add_filter('service', service_name)
        return await self.advanced_search()

    async def search_port(self, port: int) -> dict[str, Any]:
        """Search for hosts with an open port."""
        self.add_filter('port', str(port))
        return await self.advanced_search()

    async def search_country(self, country_code: str) -> dict[str, Any]:
        """Search for hosts in a country."""
        self.add_filter('country_code', country_code)
        return await self.advanced_search()

    async def search_cloud_provider(self, provider: str) -> dict[str, Any]:
        """Search for hosts on a cloud provider."""
        self.add_filter('cloud_provider', provider)
        return await self.advanced_search()

    async def search_http_status(self, status_code: int) -> dict[str, Any]:
        """Search for hosts with an HTTP status code."""
        self.add_filter('http_status_code', str(status_code))
        return await self.advanced_search()

    async def search_certificate(self, filter_name: str, value: str) -> dict[str, Any]:
        """Search for hosts with matching certificate properties."""
        if filter_name not in self.CERT_FILTERS:
            valid_filters = ', '.join(self.CERT_FILTERS)
            raise ValueError(f'Invalid certificate filter: {filter_name}. Valid filters: {valid_filters}')

        self.add_filter(filter_name, value)
        return await self.advanced_search()

    async def search_with_dns(self, dns_type: str, value: str) -> dict[str, Any]:
        """Search for hosts with a matching DNS record."""
        dns_filter = f'dns_{dns_type.lower()}'
        if dns_filter not in self.NETWORK_FILTERS:
            valid_filters = [f for f in self.NETWORK_FILTERS if f.startswith('dns_')]
            valid_types = ', '.join(f.replace('dns_', '') for f in valid_filters)
            raise ValueError(f'Invalid DNS type: {dns_type}. Valid types: {valid_types}')

        self.add_filter(dns_filter, value)
        return await self.advanced_search()

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

    async def extract_data_from_search_results(self, results: dict[str, Any]) -> None:
        """Collect normalized results from a search response."""
        if 'hosts' not in results:
            return

        # Store the raw results
        self.total_results['search_results'].append(results)

        # Extract data similar to domain details
        await self.extract_data_from_domain_details(results)

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

                # If filters are set, perform an advanced search
                if self.filters:
                    search_results = await self.advanced_search(session)
                    await self.extract_data_from_search_results(search_results)

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

    async def get_all_results(self) -> dict[str, Any]:
        """Return all collected results."""
        return self.total_results

    async def process(
        self,
        proxy: bool = False,
        filters: dict[str, str] | None = None,
    ) -> SourceExecutionReport | None:
        """Run the FullHunt search.

        Args:
            proxy: Whether to use a proxy for requests.
            filters: Optional search filters.

        """
        self.proxy = proxy
        self._report = None

        # Apply filters if provided
        if filters:
            self.add_filters(filters)

        await self.do_search()
        return self._report
