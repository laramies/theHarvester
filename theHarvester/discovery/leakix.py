import asyncio
import logging
from typing import TYPE_CHECKING

from aiohttp import ClientError

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from aiohttp import ClientSession

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

    async def _fetch(self, session: ClientSession) -> FetcherResponse | None:
        responses = await AsyncFetcher.fetch_all(
            [self.url],
            session=session,
            json=True,
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

    async def do_search(self, session: ClientSession | None = None) -> SourceExecutionReport | None:
        if session is None:
            headers = {'User-Agent': Core.get_user_agent(), 'accept': 'application/json', 'api-key': self.api_key}
            try:
                async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as owned_session:
                    return await self.do_search(owned_session)
            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)
            except ClientError, OSError:
                logger.info('LeakIX session failed')
                return SourceExecutionReport('failed', 'transport-error')

        try:
            response = await self._fetch(session)
            if response is not None and response.status == 429:
                delay = self._limited_for_seconds(response.headers.get('x-limited-for'))
                if delay is not None:
                    logger.info(f'LeakIX rate limited; retrying once in {delay:g} seconds')
                    await asyncio.sleep(delay)
                    response = await self._fetch(session)
        except OSError, RuntimeError, ValueError:
            logger.info('LeakIX request failed')
            return SourceExecutionReport('failed', 'transport-error')

        if response is None:
            logger.info('LeakIX request failed')
            return SourceExecutionReport('failed', 'transport-error')
        if error := provider_http_error(response):
            logger.info(f'LeakIX request failed with HTTP {response.status}')
            return SourceExecutionReport(*error)
        if not isinstance(response.body, list):
            logger.info('LeakIX returned a malformed response')
            return SourceExecutionReport('failed', 'invalid-response')

        malformed = False
        for item in response.body:
            if not isinstance(item, dict):
                malformed = True
                continue
            candidate = item.get('subdomain')
            if candidate is not None and not isinstance(candidate, str):
                malformed = True
                continue
            normalized = normalize_scoped_hostname(candidate, self.word)
            if normalized:
                self.totalhosts.add(normalized)
        return SourceExecutionReport('failed', 'invalid-response') if malformed else None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return set()

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
