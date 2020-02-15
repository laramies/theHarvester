from typing import Coroutine
from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchThreatcrowd:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results: str = ""
        self.totalresults: str = ""
        self.proxy = False

    async def do_search(self):
        base_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            responses = await AsyncFetcher.fetch_all([base_url], headers=headers, proxy=self.proxy)
            self.results = responses[0]
        except Exception as e:
            print(e)
        self.totalresults += self.results

    async def get_hostnames(self) -> Coroutine:
        return await myparser.Parser(self.results, self.word).hostnames()

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        await self.get_hostnames()
