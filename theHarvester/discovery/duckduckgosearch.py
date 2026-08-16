from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchDuckDuckGo:
    def __init__(self, word, limit) -> None:
        self.word = word
        self.results = ''
        self.totalresults = ''
        self.dorks: list[str] = []
        self.links: list[str] = []
        self.database = 'https://duckduckgo.com/?q='
        self.api = 'https://api.duckduckgo.com/?q=x&format=json&pretty=1'  # Currently using API.
        self.quantity = '100'
        self.limit = limit
        self.proxy: bool = False

    async def do_search(self) -> None:
        # Query only the provider; URLs in the response are evidence, not crawl targets.
        url = self.api.replace('x', self.word)
        headers = {'User-Agent': Core.get_user_agent()}
        first_resp = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        self.results = first_resp[0]
        self.totalresults += self.results

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to search once since using API.
