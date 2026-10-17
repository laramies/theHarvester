from __future__ import annotations

import logging
from ipaddress import ip_address

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchOTILabs:
    """Search the OTI Labs Domain Intelligence API for subdomains and live host addresses.

    One request to the subdomains endpoint returns the names the API found in certificate
    transparency logs and passive DNS, and the hosts that resolved when it last checked them.
    ``wait=1`` asks the API to wait for all of its upstream sources before answering.
    """

    API_HOST = 'domain-intelligence-api.p.rapidapi.com'

    def __init__(self, word: str) -> None:
        self.word = word
        self.key = Core.otilabs_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('otilabs')
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'X-RapidAPI-Key': self.key, 'X-RapidAPI-Host': self.API_HOST}
        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as session:
            response = await AsyncFetcher.fetch(
                session=session,
                url=f'https://{self.API_HOST}/domain/{self.word}/subdomains',
                params={'wait': '1'},
                json=True,
                include_metadata=True,
            )
        if error := provider_http_error(response):
            return SourceExecutionReport(*error)
        assert isinstance(response, FetcherResponse)
        body = response.body
        if not isinstance(body, dict) or not isinstance(body.get('subdomains'), list):
            return SourceExecutionReport('failed', 'invalid-response')
        live = body.get('live', [])
        if not isinstance(live, list):
            return SourceExecutionReport('failed', 'invalid-response')

        malformed = False
        for name in body['subdomains']:
            if not isinstance(name, str):
                malformed = True
                continue
            if hostname := normalize_scoped_hostname(name, self.word):
                self.totalhosts.add(hostname)
        for item in live:
            if not isinstance(item, dict) or not isinstance(item.get('host'), str):
                malformed = True
                continue
            hostname = normalize_scoped_hostname(item['host'], self.word)
            if hostname is None:
                continue
            self.totalhosts.add(hostname)
            address = item.get('ip')
            if isinstance(address, str):
                try:
                    self.totalips.add(str(ip_address(address)))
                except ValueError:
                    pass  # a CNAME target rather than an address
        if malformed:
            return SourceExecutionReport('failed', 'invalid-response')

        sources = body.get('sources_used')
        pending = isinstance(sources, list) and any(
            isinstance(source, str) and source.endswith(': enriching') for source in sources
        )
        if pending or body.get('live_count', 0) is None:
            # The API answered before its live check finished, so a later run can return more addresses.
            return SourceExecutionReport('partial', 'enrichment-pending')
        count, returned = body.get('count'), body.get('returned')
        if isinstance(count, int) and isinstance(returned, int) and count > returned:
            return SourceExecutionReport('partial', 'result-cap')
        return None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except Exception as error:
            logger.info('OTI Labs search failed: %s', type(error).__name__)
            return SourceExecutionReport('failed', 'transport-error')
