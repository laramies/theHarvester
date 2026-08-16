import asyncio
import logging

from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchCrtsh:
    RUNTIME_SECONDS = 60.0

    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False

    async def do_search(self) -> tuple[list, SourceExecutionReport | None]:
        data: set = set()
        url = f'https://crt.sh/?q=%25.{self.word}&exclude=expired&deduplicate=Y&output=json'
        response = None
        failure_reason = 'transport-error'
        try:
            max_attempts = 3
            for attempt in range(max_attempts):
                responses = await AsyncFetcher.fetch_all(
                    [url],
                    json=True,
                    proxy=self.proxy,
                    include_metadata=True,
                )
                result = responses[0] if responses else None
                if isinstance(result, FetcherResponse):
                    if 200 <= result.status < 300 and isinstance(result.body, list):
                        response = result.body
                        break
                    failure_reason = f'http-{result.status}' if not 200 <= result.status < 300 else 'invalid-response'
                    if result.status == 429:
                        return [], SourceExecutionReport('rate-limited', failure_reason)
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2)

            if response is None:
                logger.info(f'No valid response from crt.sh after {max_attempts} attempts.')
                return [], SourceExecutionReport('failed', failure_reason)

            data = set([(dct['name_value'][2:] if dct['name_value'][:2] == '*.' else dct['name_value']) for dct in response])
            data = {domain for domain in data if domain[0] != '*'}
        except KeyError as ke:
            logger.info(f'Missing expected key in response: {ke}')
            return [], SourceExecutionReport('failed', 'invalid-response')
        except Exception as e:
            logger.info(f'Unexpected error: {e}')
            return [], SourceExecutionReport('failed', 'unexpected-error')
        clean: list = []
        for x in data:
            pre = x.split()
            for y in pre:
                clean.append(y)
        return clean, None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            async with asyncio.timeout(self.RUNTIME_SECONDS):
                data, report = await self.do_search()
        except TimeoutError:
            data = []
            report = SourceExecutionReport('failed', 'runtime-limit')
        self.data = data
        return report

    async def get_hostnames(self) -> list:
        return self.data
