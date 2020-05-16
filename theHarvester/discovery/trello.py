from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import random
import asyncio


class SearchTrello:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = 300
        self.trello_urls = []
        self.hostnames = []
        self.counter = 0
        self.proxy = False

    async def do_search(self):
        base_url = f'https://{self.server}/search?num=300&start=xx&hl=en&q=site%3Atrello.com%20{self.word}'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 20) if num <= self.limit]
        # limit is 20 as that is the most results google will show per num
        headers = {'User-Agent': googleUA}
        for url in urls:
            try:
                resp = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
                self.results = resp[0]
                if await search(self.results):
                    try:
                        self.results = await google_workaround(base_url)
                        if isinstance(self.results, bool):
                            print('Google is blocking your ip and the workaround, returning')
                            return
                    except Exception as e:
                        print(e)
                self.totalresults += self.results
                await asyncio.sleep(get_delay() - .5)
            except Exception as e:
                print(f'An exception has occurred in trello: {e}')

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_urls(self):
        try:
            rawres = myparser.Parser(self.totalresults, 'trello.com')
            self.trello_urls = set(await rawres.urls())
            self.totalresults = ''
            # reset what totalresults as before it was just google results now it is trello results
            headers = {'User-Agent': random.choice(['curl/7.37.0', 'Wget/1.19.4'])}
            # do not change the headers
            responses = await AsyncFetcher.fetch_all(self.trello_urls, headers=headers, proxy=self.proxy)
            for response in responses:
                self.totalresults += response

            rawres = myparser.Parser(self.totalresults, self.word)
            self.hostnames = await rawres.hostnames()
        except Exception as e:
            print(f'Error occurred: {e}')

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        await self.get_urls()
        print(f'\tSearching {self.counter} results.')

    async def get_results(self) -> tuple:
        return await self.get_emails(), self.hostnames, self.trello_urls
