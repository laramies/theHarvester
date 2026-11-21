import csv
from ipaddress import ip_address

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchBufferover:
    def __init__(self, word: str) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        metadata = await AsyncFetcher.fetch_one(
            url,
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
        )
        if error := provider_http_error(metadata):
            return SourceExecutionReport(*error)
        assert isinstance(metadata, FetcherResponse)
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
