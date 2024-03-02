import asyncio
from typing import Any

import requests
import ujson

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import intelxparser


class SearchIntelx:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.intelx_key()
        if self.key is None:
            raise MissingKey('Intelx')
        self.database = 'https://2.intelx.io'
        self.results: Any = None
        self.info: tuple[Any, ...] = ()
        self.limit: int = 10000
        self.proxy = False
        self.offset = -1

    async def do_search(self) -> None:
        try:
            # Based on: https://github.com/IntelligenceX/SDK/blob/master/Python/intelxapi.py
            # API requests self identification
            # https://intelx.io/integrations
            headers = {
                'x-key': self.key,
                'User-Agent': f'{Core.get_user_agent()}-theHarvester',
            }
            data = {
                'term': self.word,
                'buckets': [],
                'lookuplevel': 0,
                'maxresults': self.limit,
                'timeout': 5,
                'datefrom': '',
                'dateto': '',
                'sort': 2,
                'media': 0,
                'terminate': [],
                'target': 0,
            }

            total_resp = requests.post(f'{self.database}/phonebook/search', headers=headers, json=data)
            phonebook_id = ujson.loads(total_resp.text)['id']
            await asyncio.sleep(5)

            # Fetch results from phonebook based on ID
            resp = await AsyncFetcher.fetch_all(
                [f'{self.database}/phonebook/search/result?id={phonebook_id}&limit={self.limit}&offset={self.offset}'],
                headers=headers,
                json=True,
                proxy=self.proxy,
            )
            resp = resp[0]
            self.results = resp  # TODO: give self.results more appropriate typing
        except Exception as e:
            print(f'An exception has occurred in Intelx: {e}')

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()
        intelx_parser = intelxparser.Parser()
        # TODO: give self.info more appropriate typing
        self.info = await intelx_parser.parse_dictionaries(self.results)

    async def get_emails(self):
        return self.info[0]

    async def get_interestingurls(self):
        # TODO parse add return hostnames for subdomains of urls
        return self.info[1]
