from typing import Any

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from theHarvester.parsers import venacusparser


class SearchVenacus:
    def __init__(self, word: str, limit=1000, offset_doc=0) -> None:
        self.word = word
        self.key = Core.venacus_key()
        if self.key is None:
            raise MissingKey('Venacus')
        self.base_url = 'https://api.venacus.com'
        self.results: list[dict[str, Any]] = []
        self.parsed: dict[str, Any] = {}
        self.proxy = False
        self.offset_doc = offset_doc
        self.offset_in_doc = 0
        self.ai = False
        self.more = True
        self.limit = limit

    async def do_search(self) -> None:
        total_results = []
        result_count = 0

        try:
            headers = {
                'Authorization': f'Bearer {self.key}',
                'User-Agent': f'{Core.get_user_agent()}-theHarvester',
            }

            async with aiohttp.ClientSession() as session:
                while self.more and result_count < self.limit:
                    query = {
                        'q': self.word,
                        'offset_doc': self.offset_doc,
                        'offset_in_doc': self.offset_in_doc,
                        'limit': 100,
                        'ai': 'true' if self.ai else 'false',
                    }

                    async with session.get(f'{self.base_url}/v1/search/', headers=headers, params=query) as total_resp:
                        search_data = await total_resp.json()
                        current_results = search_data.get('data', [])

                        if not current_results:
                            print('No more results found.')
                            break

                        total_results.extend(current_results)
                        result_count += len(current_results)

                        self.offset_doc = search_data.get('offset_doc', 0)
                        self.offset_in_doc = search_data.get('offset_in_doc', 0)

                        self.more = search_data.get('more', False)

                self.results = total_results
                if not self.results:
                    print('No results found.')

        except Exception as e:
            print(f'An exception has occurred in Venacus: {e}')

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()
        parser = venacusparser.Parser()
        self.parsed = await parser.parse_text_tokens(self.results)  # type: ignore

    async def get_people(self) -> list[dict[str, str]]:
        if 'people' not in self.parsed:
            return []
        return self.parsed['people']

    async def get_emails(self) -> set[str]:
        if 'emails' not in self.parsed:
            return set()
        return self.parsed['emails']

    async def get_ips(self) -> set[str]:
        if 'ips' not in self.parsed:
            return set()
        return self.parsed['ips']

    async def get_interestingurls(self) -> set[str]:
        if 'urls' not in self.parsed:
            return set()
        return self.parsed['urls']
