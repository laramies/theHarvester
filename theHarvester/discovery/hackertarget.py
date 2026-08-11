# theHarvester/discovery/hackertarget.py
from ipaddress import ip_address

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


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
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        url = f'{self.hostname}/hostsearch/?q={self.word}'
        if self.key:
            url = f'{url}&apikey={self.key}'
        responses = await AsyncFetcher.fetch_all(
            [url],
            headers=headers,
            proxy=self.proxy,
            include_metadata=True,
        )
        response = responses[0] if responses else None
        if not isinstance(response, FetcherResponse):
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if response.status == 429:
            self.execution_status = 'rate-limited'
            self.stop_reason = 'http-429'
            return
        if not 200 <= response.status < 300:
            self.execution_status = 'failed'
            self.stop_reason = f'http-{response.status}'
            return
        if not isinstance(response.body, str) or not response.body.strip():
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return

        normalized_body = response.body.casefold().strip()
        if 'api count exceeded' in normalized_body:
            self.execution_status = 'rate-limited'
            self.stop_reason = 'quota-exhausted'
            return
        if normalized_body.startswith('no records found'):
            return

        parsed_rows = 0
        for line in response.body.splitlines():
            hostname, separator, address = line.partition(',')
            normalized_hostname = normalize_scoped_hostname(hostname, self.word)
            if not separator or normalized_hostname is None:
                continue
            try:
                normalized_address = str(ip_address(address.strip()))
            except ValueError:
                continue
            self.totalhosts.add(normalized_hostname)
            self.totalips.add(normalized_address)
            parsed_rows += 1
        if not parsed_rows:
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        await self.do_search()

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips
