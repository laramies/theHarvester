from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchHunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = limit
        self.start = start
        self.key = Core.hunter_key()
        if self.key is None:
            raise MissingKey('Hunter')
        self.total_results = ""
        self.counter = start
        self.database = f'https://api.hunter.io/v2/domain-search?domain={self.word}&api_key={self.key}&limit={self.limit}'
        self.proxy = False

    async def do_search(self):
        responses = await AsyncFetcher.fetch_all([self.database], headers={'User-Agent': Core.get_user_agent()},
                                                 proxy=self.proxy)
        self.total_results += responses[0]

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()

    async def get_profiles(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.profiles()
