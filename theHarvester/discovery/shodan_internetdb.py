import logging
from ipaddress import ip_address

import aiodns

from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.hostchecker import resolve_ip_addresses
from theHarvester.lib.hostnames import normalize_scoped_hostname

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

    async def do_search(self) -> None:
        # Resolve the domain to IP addresses first
        try:
            resolved_ips = await resolve_ip_addresses(self.word)
        except aiodns.error.DNSError:
            logger.info(f'Shodan InternetDB: Could not resolve domain {self.word}')
            return

        if not resolved_ips:
            logger.info(f'Shodan InternetDB: No IPs resolved for {self.word}')
            return

        # Query InternetDB for each resolved IP
        requested_ips = list(resolved_ips)
        urls = [f'https://internetdb.shodan.io/{ip}' for ip in requested_ips]
        try:
            responses = await AsyncFetcher.fetch_all(urls, json=True, proxy=self.proxy)
        except Exception:
            logger.info('Shodan InternetDB request failed')
            return

        for requested_ip, response in zip(requested_ips, responses, strict=False):
            if not isinstance(response, dict):
                continue

            # InternetDB returns a 404 as an empty JSON object or with a "detail" key
            # when no data is found for an IP. Skip those.
            if 'detail' in response:
                continue

            try:
                response_ip = str(ip_address(response.get('ip', '')))
            except ValueError:
                continue
            if response_ip != requested_ip:
                continue
            self.totalips.add(response_ip)

            # Collect hostnames that match our target domain
            for hostname in response.get('hostnames', []):
                if normalized := normalize_scoped_hostname(hostname, self.word):
                    self.totalhosts.add(normalized)

            # Collect ports
            for port in response.get('ports', []):
                if isinstance(port, int):
                    self.ports.add(port)

            # Collect CVEs / vulnerabilities
            for vuln in response.get('vulns', []):
                if isinstance(vuln, str):
                    self.vulns.add(vuln)

            # Collect tags
            for tag in response.get('tags', []):
                if isinstance(tag, str):
                    self.tags.add(tag)

            # Collect CPEs
            for cpe in response.get('cpes', []):
                if isinstance(cpe, str):
                    self.cpes.add(cpe)

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

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
