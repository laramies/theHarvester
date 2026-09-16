import logging
from ipaddress import ip_address

import aiodns

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.hostchecker import resolve_ip_addresses
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchShodanInternetDB:
    """Search Shodan InternetDB for IP intelligence data.

    Shodan InternetDB (https://internetdb.shodan.io/) is a free API that
    provides basic information about IP addresses including open ports,
    hostnames, vulnerabilities (CVEs), tags, and CPEs. No API key is required.

    This module first resolves the target domain to its IP addresses, then
    queries InternetDB for each IP to gather associated hostnames and other
    intelligence.
    """

    def __init__(self, word) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.ports: set = set()
        self.vulns: set = set()
        self.tags: set = set()
        self.cpes: set = set()
        self.proxy = False

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.totalips or self.ports or self.vulns or self.tags or self.cpes)

    async def do_search(self) -> SourceExecutionReport | None:
        # Resolve the domain to IP addresses first
        try:
            resolved_ips = await resolve_ip_addresses(self.word)
        except aiodns.error.DNSError:
            logger.info(f'Shodan InternetDB: Could not resolve domain {self.word}')
            return SourceExecutionReport('failed', 'dns-resolution-failed')

        if not resolved_ips:
            logger.info(f'Shodan InternetDB: No IPs resolved for {self.word}')
            return None

        # Query InternetDB for each resolved IP
        requested_ips = list(resolved_ips)
        urls = [f'https://internetdb.shodan.io/{ip}' for ip in requested_ips]
        try:
            responses = await AsyncFetcher.fetch_all(urls, json=True, proxy=self.proxy, include_metadata=True)
        except OSError, RuntimeError, ValueError:
            logger.info('Shodan InternetDB request failed')
            return SourceExecutionReport('failed', 'transport-error')

        report = None
        for index, requested_ip in enumerate(requested_ips):
            response = responses[index] if index < len(responses) else None
            if isinstance(response, FetcherResponse) and response.status == 404:
                continue
            if failure := provider_http_error(response):
                report = SourceExecutionReport(*failure)
                continue
            assert isinstance(response, FetcherResponse)
            payload = response.body
            if not isinstance(payload, dict):
                report = SourceExecutionReport('failed', 'invalid-response')
                continue

            # Older InternetDB responses represented missing data with a detail object.
            if 'detail' in payload:
                continue

            try:
                response_ip = str(ip_address(payload.get('ip', '')))
            except ValueError:
                report = SourceExecutionReport('failed', 'invalid-response')
                continue
            if response_ip != requested_ip:
                report = SourceExecutionReport('failed', 'invalid-response')
                continue
            self.totalips.add(response_ip)

            fields = {name: payload.get(name, []) for name in ('hostnames', 'ports', 'vulns', 'tags', 'cpes')}
            if any(not isinstance(values, list) for values in fields.values()):
                report = SourceExecutionReport('failed', 'invalid-response')
                continue

            # Collect hostnames that match our target domain
            for hostname in fields['hostnames']:
                if normalized := normalize_scoped_hostname(hostname, self.word):
                    self.totalhosts.add(normalized)

            # Collect ports
            for port in fields['ports']:
                if isinstance(port, int):
                    self.ports.add(port)

            # Collect CVEs / vulnerabilities
            for vuln in fields['vulns']:
                if isinstance(vuln, str):
                    self.vulns.add(vuln)

            # Collect tags
            for tag in fields['tags']:
                if isinstance(tag, str):
                    self.tags.add(tag)

            # Collect CPEs
            for cpe in fields['cpes']:
                if isinstance(cpe, str):
                    self.cpes.add(cpe)
        if report is not None and self._has_results():
            return SourceExecutionReport('partial', report.stop_reason)
        return report

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_ports(self) -> set:
        return self.ports

    async def get_vulns(self) -> set:
        return self.vulns

    async def get_tags(self) -> set:
        return self.tags

    async def get_cpes(self) -> set:
        return self.cpes

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
