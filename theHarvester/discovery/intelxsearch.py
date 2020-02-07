from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import intelxparser
import asyncio


class SearchIntelx:

    def __init__(self, word, limit):
        self.word = word
        # default key is public key
        self.key = Core.intelx_key()
        if self.key is None:
            raise MissingKey(True)
        self.database = 'https://public.intelx.io/'
        self.results = None
        self.info = ()
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        try:
            user_agent = Core.get_user_agent()
            headers = {'User-Agent': user_agent, 'x-key': self.key}
            # data is json that corresponds to what we are searching for, sort:2 means sort by most relevant
            data = f'{{"term": "{self.word}", "maxresults": {self.limit}, "media": 0, "sort": 2 , "terminate": []}}'
            resp = await AsyncFetcher.post_fetch(url=f'{self.database}phonebook/search', headers=headers, data=data,
                                                 json=True, proxy=self.proxy)
            uuid = resp['id']
            # grab uuid to send get request to fetch data
            await asyncio.sleep(2)
            url = f'{self.database}phonebook/search/result?id={uuid}&offset=0&limit={self.limit}'
            resp = await AsyncFetcher.fetch_all([url], headers=headers, json=True, proxy=self.proxy)
            resp = resp[0]
            # TODO: Check if more results can be gathered depending on status
            self.results = resp
        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        intelx_parser = intelxparser.Parser()
        self.info = await intelx_parser.parse_dictionaries(self.results)
        # Create parser and set self.info to tuple returned from parsing text.

    async def get_emails(self):
        return self.info[0]

    async def get_hostnames(self):
        return self.info[1]
