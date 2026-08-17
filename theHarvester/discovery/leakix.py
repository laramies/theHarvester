import asyncio
import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchLeakix:
    """Find subdomains through LeakIX's documented subdomain endpoint."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.api_key = (Core.leakix_key() or '').strip()
        if not self.api_key:
            raise MissingKey('LeakIX')
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.url = f'https://leakix.net/api/subdomains/{word}'

    async def _fetch(self) -> FetcherResponse | None:
        responses = await AsyncFetcher.fetch_all(
            [self.url],
            headers={
                'User-Agent': Core.get_user_agent(),
                'accept': 'application/json',
                'api-key': self.api_key,
            },
            json=True,
            proxy=self.proxy,
            include_metadata=True,
        )
        response = responses[0] if responses else None
        return response if isinstance(response, FetcherResponse) else None

    @staticmethod
    def _limited_for_seconds(value: str | None) -> float | None:
        if value is None:
            return None
        try:
            delay = float(value[:-2]) / 1000 if value.endswith('ms') else float(value.removesuffix('s'))
        except ValueError:
            return None
        return delay if 0 <= delay <= 60 else None

    async def do_search(self) -> None:
        try:
            response = await self._fetch()
            if response is not None and response.status == 429:
                delay = self._limited_for_seconds(response.headers.get('x-limited-for'))
                if delay is not None:
                    logger.info(f'LeakIX rate limited; retrying once in {delay:g} seconds')
                    await asyncio.sleep(delay)
                    response = await self._fetch()
        except OSError, RuntimeError, ValueError:
            logger.info('LeakIX request failed')
            return

        if response is None:
            logger.info('LeakIX request failed')
            return
        if not 200 <= response.status < 300:
            logger.info(f'LeakIX request failed with HTTP {response.status}')
            return
        if not isinstance(response.body, list):
            logger.info('LeakIX returned a malformed response')
            return

        for item in response.body:
            if not isinstance(item, dict):
                continue
            normalized = normalize_scoped_hostname(item.get('subdomain'), self.word)
            if normalized:
                self.totalhosts.add(normalized)

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return set()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
