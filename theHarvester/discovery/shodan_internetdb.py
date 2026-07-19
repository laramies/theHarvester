import asyncio
import socket

from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.output import output_logger


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
        self.word = word
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
            addr_infos = await asyncio.to_thread(socket.getaddrinfo, self.word, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            output_logger.info(f'Shodan InternetDB: Could not resolve domain {self.word}')
            return

        # Deduplicate IPs from the resolution results
        resolved_ips: set[str] = set()
        for _family, _type, _proto, _canonname, sockaddr in addr_infos:
            ip = sockaddr[0]
            if isinstance(ip, str):
                resolved_ips.add(ip)

        if not resolved_ips:
            output_logger.info(f'Shodan InternetDB: No IPs resolved for {self.word}')
            return

        # Query InternetDB for each resolved IP
        urls = [f'https://internetdb.shodan.io/{ip}' for ip in resolved_ips]
        responses = await AsyncFetcher.fetch_all(urls, json=True, proxy=self.proxy)

        for response in responses:
            if not isinstance(response, dict):
                continue

            # InternetDB returns a 404 as an empty JSON object or with a "detail" key
            # when no data is found for an IP. Skip those.
            if 'detail' in response:
                continue

            # Collect hostnames that match our target domain
            for hostname in response.get('hostnames', []):
                if isinstance(hostname, str) and (hostname == self.word or hostname.endswith('.' + self.word)):
                    self.totalhosts.add(hostname)

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

            # Add the IP if there was any data
            if (
                response.get('hostnames')
                or response.get('ports')
                or response.get('vulns')
                or response.get('tags')
                or response.get('cpes')
            ):
                ip_str = response.get('ip', '')
                if ip_str:
                    self.totalips.add(str(ip_str))

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
