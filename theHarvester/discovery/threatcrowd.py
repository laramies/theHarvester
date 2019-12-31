from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchThreatcrowd:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results: str = ""
        self.totalresults: str = ""

    async def do_search(self):
        base_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            responses = await AsyncFetcher.fetch_all([base_url], headers=headers)
            self.results = responses[0]
        except Exception as e:
            print(e)
        self.totalresults += self.results

    async def get_hostnames(self) -> set:
        return myparser.Parser(self.results, self.word).hostnames()

    async def process(self):
        await self.do_search()
        await self.get_hostnames()
