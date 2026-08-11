import asyncio
import logging

from theHarvester.lib.core import AsyncFetcher, FetcherResponse

logger = logging.getLogger(__name__)


class SearchCrtsh:
    RUNTIME_SECONDS = 60.0

    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> list:
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
                        self.execution_status = 'rate-limited'
                        self.stop_reason = failure_reason
                        return []
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2)

            if response is None:
                self.execution_status = 'failed'
                self.stop_reason = failure_reason
                logger.info(f'No valid response from crt.sh after {max_attempts} attempts.')
                return []

            data = set([(dct['name_value'][2:] if dct['name_value'][:2] == '*.' else dct['name_value']) for dct in response])
            data = {domain for domain in data if domain[0] != '*'}
        except KeyError as ke:
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            logger.info(f'Missing expected key in response: {ke}')
        except Exception as e:
            self.execution_status = 'failed'
            self.stop_reason = 'unexpected-error'
            logger.info(f'Unexpected error: {e}')
        clean: list = []
        for x in data:
            pre = x.split()
            for y in pre:
                clean.append(y)
        return clean

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        try:
            async with asyncio.timeout(self.RUNTIME_SECONDS):
                data = await self.do_search()
        except TimeoutError:
            self.execution_status = 'failed'
            self.stop_reason = 'runtime-limit'
            data = []
        self.data = data

    async def get_hostnames(self) -> list:
        return self.data
