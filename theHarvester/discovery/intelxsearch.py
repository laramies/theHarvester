from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import intelxparser
import asyncio
import json
import requests


class SearchIntelx:

    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.intelx_key()
        if self.key is None:
            raise MissingKey('Intelx')
        self.database = 'https://2.intelx.io'
        self.results = None
        self.info = ()
        self.limit: int = 10000
        self.proxy = False
        self.offset = -1

    async def do_search(self) -> None:
        try:
            # Based on: https://github.com/IntelligenceX/SDK/blob/master/Python/intelxapi.py
            # API requests self identification
            # https://intelx.io/integrations
            headers = {'x-key': self.key, 'User-Agent': f'{Core.get_user_agent()}-theHarvester'}
            data = {
                "term": self.word,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": self.limit,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 2,
                "media": 0,
                "terminate": [],
                "target": 0
            }

            total_resp = requests.post(f'{self.database}/phonebook/search', headers=headers, json=data)
            phonebook_id = json.loads(total_resp.text)['id']
            await asyncio.sleep(2)

            # Fetch results from phonebook based on ID
            resp = await AsyncFetcher.fetch_all(
                [f'{self.database}/phonebook/search/result?id={phonebook_id}&limit={self.limit}&offset={self.offset}'],
                headers=headers, json=True, proxy=self.proxy)
            resp = resp[0]
            self.results = resp
        except Exception as e:
            print(f'An exception has occurred in Intelx: {e}')

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()
        intelx_parser = intelxparser.Parser()
        self.info = await intelx_parser.parse_dictionaries(self.results)

    async def get_emails(self):
        return self.info[0]

    async def get_interestingurls(self):
        return self.info[1]
