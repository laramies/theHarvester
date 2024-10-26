import asyncio
from typing import Any
from urllib.parse import urlparse

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from theHarvester.parsers import intelxparser


class SearchIntelx:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.intelx_key()
        if self.key is None:
            raise MissingKey('Intelx')
        self.database = 'https://2.intelx.io'
        self.results: dict[str, Any] = {}
        self.info: tuple[list[str], list[str], list[str]] = ([], [], [])
        self.limit: int = 10000
        self.proxy = False
        self.offset = 0

    async def do_search(self) -> None:
        try:
            headers = {
                'x-key': self.key,
                'User-Agent': f'{Core.get_user_agent()}-theHarvester',
                'Content-Type': 'application/json',
            }
            data = {
                'term': self.word,
                'buckets': [],
                'lookuplevel': 0,
                'maxresults': self.limit,
                'timeout': 5,
                'datefrom': '',
                'dateto': '',
                'sort': 4,  # Sort by date descending for faster relevant results
                'media': 0,
                'terminate': [],
                'target': 0,
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(f'{self.database}/phonebook/search', headers=headers, json=data) as total_resp:
                    search_data = await total_resp.json()
                    if not search_data['success']:
                        print(f'Error: {search_data["message"]}')
                        return
                    phonebook_id = search_data['id']

                await asyncio.sleep(2)  # Reduced sleep time as 5s is excessive

                async with session.get(
                    f'{self.database}/phonebook/search/result?id={phonebook_id}&limit={self.limit}&offset={self.offset}',
                    headers=headers,
                ) as resp:
                    self.results = await resp.json()

        except Exception as e:
            print(f'An exception has occurred in Intelx: {e}')

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()
        intelx_parser = intelxparser.Parser()
        self.info = await intelx_parser.parse_dictionaries(self.results)

    async def get_emails(self) -> list[str]:
        return self.info[0]

    async def get_interestingurls(self) -> tuple[list[str], list[str]]:
        urls = self.info[1]
        subdomains = []

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain.count('.') > 1 and self.word in domain:
                    subdomains.append(domain)
            except Exception:
                continue

        return urls, list(set(subdomains))
