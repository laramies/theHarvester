import logging

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SubdomainCenter:
    def __init__(self, word):
        self.word = word
        self.results = set()
        self.server = 'https://api.subdomain.center/?domain='
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            current_url = f'{self.server}{self.word}'
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [current_url],
                headers=headers,
                proxy=self.proxy,
                json=True,
                include_metadata=True,
            )
            response = responses[0] if responses else None
            if failure := provider_http_error(response):
                logger.info(
                    f'SubdomainCenter request failed with HTTP {response.status}'
                    if isinstance(response, FetcherResponse)
                    else 'SubdomainCenter request failed'
                )
                return SourceExecutionReport(*failure)
            assert isinstance(response, FetcherResponse)
            payload = response.body
            if not isinstance(payload, list):
                logger.info('SubdomainCenter returned malformed data')
                return SourceExecutionReport('failed', 'invalid-response')
            self.results = {hostname for hostname in payload if isinstance(hostname, str) and hostname.strip()}
            if any(not isinstance(hostname, str) or not hostname.strip() for hostname in payload):
                return SourceExecutionReport('partial' if self.results else 'failed', 'invalid-response')
            return None
        except OSError, RuntimeError, ValueError:
            logger.info('SubdomainCenter request failed')
            return SourceExecutionReport('failed', 'transport-error')

    async def get_hostnames(self):
        return self.results

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
