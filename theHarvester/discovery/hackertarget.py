# theHarvester/discovery/hackertarget.py
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus

if TYPE_CHECKING:
    from collections.abc import Callable


class SearchHackerTarget:
    """Class uses the HackerTarget API to gather subdomains and IPs.

    This version supports reading a Hackertarget API key (if present) and
    appending it to the hackertarget request URLs as `apikey=<key>`.
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.hostname = 'https://api.hackertarget.com'
        self.proxy = False
        self.key = Core.hackertarget_key()

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'User-agent': Core.get_user_agent()}

        urls = [f'{self.hostname}/hostsearch/?q={self.word}']
        parsers: list[Callable[[str], tuple[int, bool]]] = [self._parse_hostsearch]
        address_query = True
        try:
            ip_network(self.word.strip(), strict=False)
        except ValueError:
            first, separator, last = self.word.strip().partition('-')
            if not separator:
                address_query = False
            else:
                try:
                    ip_address(first.strip())
                except ValueError:
                    address_query = False
                else:
                    last = last.strip()
                    try:
                        ip_address(last)
                    except ValueError:
                        address_query = last.isdecimal() and 0 <= int(last) <= 255
        if not address_query:
            urls.append(f'{self.hostname}/reversedns/?q={self.word}')
            parsers.append(self._parse_reversedns)
        if self.key:
            urls = [f'{url}&apikey={self.key}' for url in urls]
        responses = await AsyncFetcher.fetch_all(
            urls,
            headers=headers,
            proxy=self.proxy,
            include_metadata=True,
        )
        failures: list[tuple[SourceReportStatus, str]] = []
        successful_endpoints = 0
        for index, parser in enumerate(parsers):
            response = responses[index] if index < len(responses) else None
            if not isinstance(response, FetcherResponse):
                failures.append(('failed', 'transport-error'))
                continue
            if response.status == 429:
                failures.append(('rate-limited', 'http-429'))
                continue
            if not 200 <= response.status < 300:
                failures.append(('failed', f'http-{response.status}'))
                continue
            if not isinstance(response.body, str) or not response.body.strip():
                failures.append(('failed', 'invalid-response'))
                continue

            normalized_body = response.body.casefold().strip()
            if 'api count exceeded' in normalized_body:
                failures.append(('rate-limited', 'quota-exhausted'))
                continue
            if normalized_body.startswith(('no records found', 'no ptr records found')):
                successful_endpoints += 1
                continue

            parsed_rows, malformed = parser(response.body)
            if parsed_rows:
                successful_endpoints += 1
            if not parsed_rows or malformed:
                failures.append(('failed', 'invalid-response'))

        if failures:
            if successful_endpoints:
                return SourceExecutionReport('partial', failures[0][1])
            if all(status == 'rate-limited' for status, _reason in failures):
                return SourceExecutionReport('rate-limited', failures[0][1])
            return SourceExecutionReport('failed', next(reason for status, reason in failures if status == 'failed'))
        return None

    def _parse_hostsearch(self, body: str) -> tuple[int, bool]:
        parsed_rows = 0
        malformed = False
        for line in body.splitlines():
            hostname, separator, address = line.partition(',')
            normalized_hostname = normalize_scoped_hostname(hostname, self.word)
            if not separator or normalized_hostname is None:
                malformed = True
                continue
            try:
                normalized_address = str(ip_address(address.strip()))
            except ValueError:
                malformed = True
                continue
            self.totalhosts.add(normalized_hostname)
            self.totalips.add(normalized_address)
            parsed_rows += 1
        return parsed_rows, malformed

    def _parse_reversedns(self, body: str) -> tuple[int, bool]:
        parsed_rows = 0
        malformed = False
        for line in body.splitlines():
            hostname, separator, address = line.partition(',')
            if not separator:
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    malformed = True
                    continue
                address, hostname = parts
            normalized_hostname = normalize_scoped_hostname(hostname, self.word)
            if normalized_hostname is None:
                malformed = True
                continue
            try:
                normalized_address = str(ip_address(address))
            except ValueError:
                malformed = True
                continue
            self.totalhosts.add(normalized_hostname)
            self.totalips.add(normalized_address)
            parsed_rows += 1
        return parsed_rows, malformed

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips
