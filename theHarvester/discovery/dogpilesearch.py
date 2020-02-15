from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchDogpile:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'www.dogpile.com'
        self.hostname = 'www.dogpile.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        # Dogpile is hardcoded to return 10 results.
        try:
            headers = {'User-agent': Core.get_user_agent()}
            base_url = f'https://{self.server}/search/web?qsi=xx&q=%40{self.word}'
            urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
            responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
            for response in responses:
                self.total_results += response
        except Exception as e:
            print(f'Error Occurred: {e}')

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
