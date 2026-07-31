import asyncio
import logging

from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.run import SourceIncompleteError

logger = logging.getLogger(__name__)


class SearchCrtsh:
    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False

    async def do_search(self) -> list:
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
                raise SourceIncompleteError(f'No valid response from crt.sh after {max_attempts} attempts.')

            clean: set[str] = set()
            for item in response:
                for name in item['name_value'].split():
                    name = name.removeprefix('*.')
                    if name and not name.startswith('*') and not name[:4].isnumeric():
                        clean.add(name)
        except SourceIncompleteError:
            raise
        except KeyError as error:
            raise SourceIncompleteError(f'Missing expected key in crt.sh response: {error}') from error
        except Exception as error:
            raise SourceIncompleteError(f'Unexpected crt.sh error: {error}') from error
        return list(clean)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        data = await self.do_search()
        self.data = data

    async def get_hostnames(self) -> list:
        return self.data
