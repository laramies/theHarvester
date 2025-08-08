from typing import Any, ClassVar
from urllib.parse import quote

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchFullHunt:
    """Class to search FullHunt API for domain information

    FullHunt provides various endpoints for attack surface discovery:
    - Domain Details: Full domain information including hosts, DNS records, ports, etc.
    - Subdomains: Just the list of subdomains for a domain
    - Host Details: Detailed information about specific hosts
    - Data Intelligence: Access to FullHunt's attack surface database

    Supported search filters (with examples):

    General Filters:
    - domain: Domain (required for all filters) - domain:kaspersky.com
    - ip: IP address associated with the asset - ip:8.8.8.8
    - tech: Identified Technologies - tech:drupal
    - host: Specific host - host:ecommerce.kaspersky.com
    - subdomain: Subdomain - subdomain:video.kaspersky.com
    - tld: Top-Level Domain - tld:com
    - tag: Tags - tag:cdn
    - is_dos_defense: DDoS prevention solution - is_dos_defense:true

    Network Filters:
    - port: Network Port - port:80
    - has_private_ip: Has Private IP - has_private_ip:true
    - has_ipv6: Has IPv6 - has_ipv6:true
    - is_live: Is the asset live - is_live:true
    - is_resolvable: Is resolvable - is_resolvable:true
    - dns_a, dns_aaaa, dns_cname, dns_mx, dns_txt, dns_ptr, dns_ns: DNS records

    HTTP Filters:
    - http_title: HTTP Title - http_title:Nginx
    - http_status_code: HTTP Status code - http_status_code:302
    - http_favicon_hash: HTTP Favicon Hash - http_favicon_hash:9888t96t6ctsdgc9gc

    Geographic Filters:
    - country_code/country: Country Code - country_code:us
    - city: City - city:ashburn
    - asn: Autonomous System Number - asn:123124

    Cloud Filters:
    - is_cloud: Is on cloud - is_cloud:true
    - cloud_provider: Cloud Provider - cloud_provider:Linode
    - cloud_region: Cloud Region - cloud_region:us-ca

    Technology Filters:
    - product: Identified Product - product:wordpress
    - service: Identified Service - service:http

    Certificate Filters:
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
        self.key = Core.fullhunt_key()
        if self.key is None:
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

    def _get_headers(self) -> dict[str, str]:
        """Returns the headers needed for API requests"""
        return {'User-Agent': Core.get_user_agent(), 'X-API-KEY': self.key}

    async def _fetch_data(self, endpoint: str) -> dict[str, Any]:
        """Generic method to fetch data from a specific endpoint"""
        url = f'{self.BASE_URL}/{endpoint}'
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            headers=self._get_headers(),
            proxy=self.proxy,
        )
        return response[0]

    def add_filter(self, filter_name: str, filter_value: str) -> None:
        """Add a search filter to be used in advanced searches

        Args:
            filter_name: Name of the filter from the supported filter list
            filter_value: Value for the filter

        Raises:
            ValueError: If the filter name is not supported
        """
        if filter_name not in self.ALL_FILTERS:
            valid_filters = ', '.join(self.ALL_FILTERS)
            raise ValueError(f'Invalid filter name: {filter_name}. Valid filters: {valid_filters}')

        self.filters[filter_name] = filter_value

    def add_filters(self, filters: dict[str, str]) -> None:
        """Add multiple search filters at once

        Args:
            filters: Dictionary of filter name to filter value

        Raises:
            ValueError: If any filter name is not supported
        """
        for name, value in filters.items():
            self.add_filter(name, value)

    def clear_filters(self) -> None:
        """Clear all filters"""
        self.filters = {}

    def _build_query_string(self) -> str:
        """Build a query string from the current filters"""
        # Start with the domain filter which is required
        query_parts = [f'domain:{self.word}']

        # Add all other filters
        for filter_name, filter_value in self.filters.items():
            # Skip domain filter as it's already added
            if filter_name == 'domain':
                continue

            query_parts.append(f'{filter_name}:{filter_value}')

        return ' '.join(query_parts)

    async def advanced_search(self) -> dict[str, Any]:
        """Perform an advanced search using the configured filters

        This method uses the search endpoint with the filters configured via add_filter
        or add_filters methods.

        Returns:
            Dict containing the search results
        """
        query = self._build_query_string()
        encoded_query = quote(query)
        endpoint = f'search?query={encoded_query}'
        return await self._fetch_data(endpoint)

    async def get_domain_details(self) -> dict[str, Any]:
        """Get comprehensive details about a domain"""
        endpoint = f'domain/{self.word}/details'
        return await self._fetch_data(endpoint)

    async def get_subdomains(self) -> dict[str, Any]:
        """Get subdomains for a domain"""
        endpoint = f'domain/{self.word}/subdomains'
        return await self._fetch_data(endpoint)

    async def get_host_details(self, host: str) -> dict[str, Any]:
        """Get detailed information about a specific host"""
        endpoint = f'host?host={host}'
        return await self._fetch_data(endpoint)

    async def search_tech(self, tech_name: str) -> dict[str, Any]:
        """Search for hosts using a specific technology"""
        self.add_filter('tech', tech_name)
        return await self.advanced_search()

    async def search_service(self, service_name: str) -> dict[str, Any]:
        """Search for hosts running a specific service"""
        self.add_filter('service', service_name)
        return await self.advanced_search()

    async def search_port(self, port: int) -> dict[str, Any]:
        """Search for hosts with a specific open port"""
        self.add_filter('port', str(port))
        return await self.advanced_search()

    async def search_country(self, country_code: str) -> dict[str, Any]:
        """Search for hosts in a specific country"""
        self.add_filter('country_code', country_code)
        return await self.advanced_search()

    async def search_cloud_provider(self, provider: str) -> dict[str, Any]:
        """Search for hosts on a specific cloud provider"""
        self.add_filter('cloud_provider', provider)
        return await self.advanced_search()

    async def search_http_status(self, status_code: int) -> dict[str, Any]:
        """Search for hosts with a specific HTTP status code"""
        self.add_filter('http_status_code', str(status_code))
        return await self.advanced_search()

    async def search_certificate(self, filter_name: str, value: str) -> dict[str, Any]:
        """Search for hosts with specific certificate properties"""
        if filter_name not in self.CERT_FILTERS:
            valid_filters = ', '.join(self.CERT_FILTERS)
            raise ValueError(f'Invalid certificate filter: {filter_name}. Valid filters: {valid_filters}')

        self.add_filter(filter_name, value)
        return await self.advanced_search()

    async def search_with_dns(self, dns_type: str, value: str) -> dict[str, Any]:
        """Search for hosts with specific DNS records"""
        dns_filter = f'dns_{dns_type.lower()}'
        if dns_filter not in self.NETWORK_FILTERS:
            valid_filters = [f for f in self.NETWORK_FILTERS if f.startswith('dns_')]
            valid_types = ', '.join(f.replace('dns_', '') for f in valid_filters)
            raise ValueError(f'Invalid DNS type: {dns_type}. Valid types: {valid_types}')

        self.add_filter(dns_filter, value)
        return await self.advanced_search()

    async def extract_data_from_domain_details(self, details: dict[str, Any]) -> None:
        """Extract useful information from domain details response"""
        if 'hosts' not in details:
            return

        hosts = details['hosts']
        for host_data in hosts:
            # Extract subdomains
            if host_data.get('host'):
                self.total_results['hosts'].append(host_data['host'])

            # Extract IPs
            if host_data.get('ip_address'):
                self.total_results['ips'].append(host_data['ip_address'])

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
                hostname = host_data.get('host', '')

                if hostname not in self.total_results['dns_records']:
                    self.total_results['dns_records'][hostname] = {}

                for record_type, records in dns_records.items():
                    self.total_results['dns_records'][hostname][record_type] = records

            # Extract HTTP information
            if 'http_response' in host_data:
                http_info = host_data['http_response']
                hostname = host_data.get('host', '')

                if hostname not in self.total_results['http_info']:
                    self.total_results['http_info'][hostname] = {}

                for key, value in http_info.items():
                    self.total_results['http_info'][hostname][key] = value

            # Extract geographic information
            if 'geo' in host_data:
                geo_info = host_data['geo']
                hostname = host_data.get('host', '')

                if hostname not in self.total_results['geo_info']:
                    self.total_results['geo_info'][hostname] = {}

                for key, value in geo_info.items():
                    self.total_results['geo_info'][hostname][key] = value

            # Extract cloud information
            if 'cloud' in host_data:
                cloud_info = host_data['cloud']
                hostname = host_data.get('host', '')

                if hostname not in self.total_results['cloud_info']:
                    self.total_results['cloud_info'][hostname] = {}

                for key, value in cloud_info.items():
                    self.total_results['cloud_info'][hostname][key] = value

            # Extract certificate information
            if 'certificate' in host_data:
                cert_info = host_data['certificate']
                cert_info['hostname'] = host_data.get('host', '')
                self.total_results['cert_info'].append(cert_info)

        # Deduplicate results
        self.total_results['hosts'] = list(set(self.total_results['hosts']))
        self.total_results['ips'] = list(set(self.total_results['ips']))
        self.total_results['technologies'] = list(set(self.total_results['technologies']))
        self.total_results['tags'] = list(set(self.total_results['tags']))

    async def extract_data_from_search_results(self, results: dict[str, Any]) -> None:
        """Extract useful information from search results"""
        if 'hosts' not in results:
            return

        # Store the raw results
        self.total_results['search_results'].append(results)

        # Extract data similar to domain details
        await self.extract_data_from_domain_details(results)

    async def do_search(self) -> None:
        """Main search method that calls the various endpoints"""
        try:
            # First get domain details which includes most information
            domain_details = await self.get_domain_details()
            self.total_results['domain_details'] = domain_details
            await self.extract_data_from_domain_details(domain_details)

            # If no hosts found in domain details, try the dedicated subdomains endpoint
            if not self.total_results['hosts']:
                subdomains_response = await self.get_subdomains()
                if 'hosts' in subdomains_response:
                    self.total_results['hosts'] = subdomains_response['hosts']

            # If filters are set, perform an advanced search
            if self.filters:
                search_results = await self.advanced_search()
                await self.extract_data_from_search_results(search_results)

        except Exception as e:
            print(f'Error during FullHunt search: {e}')

    async def get_hostnames(self) -> list[str]:
        """Return list of discovered subdomains"""
        return self.total_results['hosts']

    async def get_ips(self) -> list[str]:
        """Return list of discovered IP addresses"""
        return self.total_results['ips']

    async def get_ports(self) -> list[int]:
        """Return list of open ports"""
        return list(self.total_results['ports'])

    async def get_technologies(self) -> list[str]:
        """Return list of technologies found"""
        return self.total_results['technologies']

    async def get_tags(self) -> list[str]:
        """Return list of tags"""
        return self.total_results['tags']

    async def get_dns_records(self) -> dict[str, dict[str, list[str]]]:
        """Return DNS records for hosts"""
        return self.total_results['dns_records']

    async def get_http_info(self) -> dict[str, dict[str, Any]]:
        """Return HTTP information for hosts"""
        return self.total_results['http_info']

    async def get_geo_info(self) -> dict[str, dict[str, Any]]:
        """Return geographic information for hosts"""
        return self.total_results['geo_info']

    async def get_cloud_info(self) -> dict[str, dict[str, Any]]:
        """Return cloud provider information for hosts"""
        return self.total_results['cloud_info']

    async def get_certificate_info(self) -> list[dict[str, Any]]:
        """Return certificate information for hosts"""
        return self.total_results['cert_info']

    async def get_all_results(self) -> dict[str, Any]:
        """Return all collected results"""
        return self.total_results

    async def process(self, proxy: bool = False, filters: dict[str, str] | None = None) -> None:
        """Main processing method

        Args:
            proxy: Whether to use a proxy for requests
            filters: Optional dictionary of filters to apply to the search
        """
        self.proxy = proxy

        # Apply filters if provided
        if filters:
            self.add_filters(filters)

        await self.do_search()
