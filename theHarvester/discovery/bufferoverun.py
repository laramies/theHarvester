import csv
from ipaddress import ip_address

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchBufferover:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
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
            return SourceExecutionReport('failed', 'transport-error')
        if metadata.status == 429:
            return SourceExecutionReport('rate-limited', 'http-429')
        if metadata.status in {401, 403}:
            return SourceExecutionReport('failed', 'access-denied')
        if not 200 <= metadata.status < 300:
            return SourceExecutionReport('failed', f'http-{metadata.status}')
        if not isinstance(metadata.body, dict) or not isinstance(metadata.body.get('Results'), list):
            return SourceExecutionReport('failed', 'invalid-response')

        results = metadata.body['Results']
        malformed = False
        for result in results:
            if not isinstance(result, str):
                malformed = True
                continue
            try:
                row = next(csv.reader([result]))
            except csv.Error, StopIteration:
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
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
