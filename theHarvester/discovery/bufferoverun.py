import csv
from ipaddress import ip_address

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchBufferover:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
            include_metadata=True,
        )
        metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
        if metadata is None:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if metadata.status == 429:
            self.execution_status = 'rate-limited'
            self.stop_reason = 'http-429'
            return
        if metadata.status in {401, 403}:
            self.execution_status = 'failed'
            self.stop_reason = 'access-denied'
            return
        if not 200 <= metadata.status < 300:
            self.execution_status = 'failed'
            self.stop_reason = f'http-{metadata.status}'
            return
        if not isinstance(metadata.body, dict) or not isinstance(metadata.body.get('Results'), list):
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return

        results = metadata.body['Results']
        malformed = False
        for result in results:
            if not isinstance(result, str):
                malformed = True
                continue
            try:
                row = next(csv.reader([result]))
            except (csv.Error, StopIteration):
                malformed = True
                continue
            if len(row) != 4:
                malformed = True
                continue
            address, _certificate_hash, _organization, hostname = (value.strip() for value in row)
            try:
                normalized_address = str(ip_address(address))
            except ValueError:
                malformed = True
                continue
            self.totalips.add(normalized_address)
            if normalized_hostname := normalize_scoped_hostname(hostname, self.word):
                self.totalhosts.add(normalized_hostname)
        if malformed:
            self.execution_status = 'partial' if self.totalhosts or self.totalips else 'failed'
            self.stop_reason = 'invalid-response'
        else:
            self.execution_status = 'completed'
            self.stop_reason = None if results else 'no-results'

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
