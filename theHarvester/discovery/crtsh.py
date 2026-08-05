import asyncio
import logging

from theHarvester.lib.core import AsyncFetcher

logger = logging.getLogger(__name__)


class SearchCrtsh:
    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False

    async def do_search(self) -> list:
        data: set = set()
        url = f'https://crt.sh/?q=%25.{self.word}&exclude=expired&deduplicate=Y&output=json'
        response = None
        try:
            max_attempts = 3
            for attempt in range(max_attempts):
                responses = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
                if responses and isinstance(responses[0], list):
                    response = responses[0]
                    break
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2)

            if response is None:
                logger.info(f'No valid response from crt.sh after {max_attempts} attempts.')
                return []

            data = set([(dct['name_value'][2:] if dct['name_value'][:2] == '*.' else dct['name_value']) for dct in response])
            data = {domain for domain in data if domain[0] != '*'}
        except KeyError as ke:
            logger.info(f'Missing expected key in response: {ke}')
        except Exception as e:
            logger.info(f'Unexpected error: {e}')
        clean: list = []
        for x in data:
            pre = x.split()
            for y in pre:
                clean.append(y)
        return clean

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        data = await self.do_search()
        self.data = data

    async def get_hostnames(self) -> list:
        return self.data
