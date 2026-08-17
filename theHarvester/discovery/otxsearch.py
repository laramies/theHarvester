import asyncio
import logging
from ipaddress import ip_address
from typing import Any

from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchOtx:
    DEFAULT_RETRY_DELAY_SECONDS = 5
    MAX_RETRY_DELAY_SECONDS = 60

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        try:
            response_list = await AsyncFetcher.fetch_all(
                [url],
                json=True,
                proxy=self.proxy,
                include_metadata=True,
            )
            response = response_list[0] if response_list and isinstance(response_list[0], FetcherResponse) else None
            if response is not None and response.status == 429:
                retry_after = response.headers.get('retry-after')
                try:
                    retry_delay = int(retry_after) if retry_after is not None else self.DEFAULT_RETRY_DELAY_SECONDS
                except ValueError:
                    retry_delay = self.DEFAULT_RETRY_DELAY_SECONDS
                if 0 <= retry_delay <= self.MAX_RETRY_DELAY_SECONDS:
                    logger.info(f'OTX rate limited; retrying once in {retry_delay} seconds')
                    await asyncio.sleep(retry_delay)
                    response_list = await AsyncFetcher.fetch_all(
                        [url],
                        json=True,
                        proxy=self.proxy,
                        include_metadata=True,
                    )
                    response = response_list[0] if response_list and isinstance(response_list[0], FetcherResponse) else None
        except OSError, RuntimeError, ValueError:
            self.totalhosts = set()
            self.totalips = set()
            logger.info('OTX request failed')
            return SourceExecutionReport('failed', 'transport-error')

        if response is None:
            logger.info('OTX request failed')
            return SourceExecutionReport('failed', 'transport-error')
        if not 200 <= response.status < 300:
            if response.status == 429:
                report = SourceExecutionReport('rate-limited', 'http-429')
            else:
                report = SourceExecutionReport('failed', f'http-{response.status}')
            logger.info(f'OTX request failed with HTTP {response.status}')
            return report

        # Expect a list with one JSON-decoded dict
        dct: Any = response.body
        if not isinstance(dct, dict):
            self.totalhosts = set()
            self.totalips = set()
            return SourceExecutionReport('failed', 'invalid-response')

        passive = dct.get('passive_dns')
        if not isinstance(passive, list):
            self.totalhosts = set()
            self.totalips = set()
            return SourceExecutionReport('failed', 'invalid-response')

        try:
            self.totalhosts = {host['hostname'] for host in passive if isinstance(host, dict) and 'hostname' in host}
            self.totalips = set()
            for record in passive:
                if not isinstance(record, dict) or not isinstance(address := record.get('address'), str):
                    continue
                try:
                    self.totalips.add(str(ip_address(address.strip())))
                except ValueError:
                    continue
        except KeyError, TypeError, ValueError:
            self.totalhosts = set()
            self.totalips = set()
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
