import asyncio
import logging
from urllib.parse import urlencode

import aiohttp

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchThc:
    """Search THC (ip.thc.org) for subdomains."""

    PROVIDER_MAX_RESULTS = 50_000

    def __init__(self, word: str, limit: int | None = None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('THC limit must be a positive integer or None')
        self.word = word
        self.limit = limit
        self.results: set = set()
        self.proxy = False
        self.max_retries = 3
        self.base_delay = 2

    async def do_search(self) -> SourceExecutionReport | None:
        requested = self.PROVIDER_MAX_RESULTS if self.limit is None else min(self.limit, self.PROVIDER_MAX_RESULTS)
        query = urlencode({'domain': self.word, 'limit': requested, 'hide_header': 'true'})
        url = f'https://ip.thc.org/api/v1/subdomains/download?{query}'
        headers = {'User-Agent': Core.get_user_agent()}

        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as session:
                for attempt in range(self.max_retries):
                    try:
                        async with session.get(url) as response:
                            if response.status == 429:
                                rate_remaining = response.headers.get('x-ratelimit-remaining', '0')
                                if attempt == self.max_retries - 1:
                                    logger.info(f'THC returned status 429 after {self.max_retries} attempts')
                                    return SourceExecutionReport('rate-limited', 'http-429')
                                wait_time = self.base_delay * (attempt + 1)
                                logger.info(
                                    f'THC rate limit hit (remaining: {rate_remaining}). Waiting {wait_time}s before retry...'
                                )
                                await asyncio.sleep(wait_time)
                                continue

                            if response.status != 200:
                                logger.info(f'THC returned status {response.status}')
                                return SourceExecutionReport('failed', f'http-{response.status}')

                            text = await response.text()
                            lines = text.splitlines()
                            for line in lines:
                                if hostname := normalize_scoped_hostname(line, self.word):
                                    self.results.add(hostname)
                            if len(lines) >= requested and (self.limit is None or self.limit > self.PROVIDER_MAX_RESULTS):
                                return SourceExecutionReport('partial', 'provider-limit')
                            return None

                    except Exception as e:
                        error_msg = str(e).lower()
                        if '429' in error_msg or 'rate' in error_msg:
                            if attempt == self.max_retries - 1:
                                logger.info(f'THC rate limit failure after {self.max_retries} attempts')
                                return SourceExecutionReport('rate-limited', 'provider-rate-limit')
                            wait_time = self.base_delay * (attempt + 1)
                            logger.info(f'THC rate limit detected. Waiting {wait_time}s before retry...')
                            await asyncio.sleep(wait_time)
                            continue
                        logger.info(f'An exception has occurred in THC: {e}')
                        return SourceExecutionReport('failed', 'transport-error')
        except (aiohttp.ClientError, OSError, ValueError) as e:
            logger.info(f'An exception has occurred in THC: {e}')
            return SourceExecutionReport('failed', 'transport-error')
        return SourceExecutionReport('failed', 'transport-error')

    async def get_hostnames(self) -> set:
        return self.results

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
