from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import asyncio


class SearchBrave:

    def __init__(self, word, limit):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = 'https://search.brave.com/search?q='
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        try:
            headers = {'User-Agent': Core.get_user_agent()}
            for offset in range(0, 50):
                # To reduce total number of requests made just search for "self.word" instead of self.word
                current_url = f'{self.server}"{self.word}"&offset={offset}&source=web&show_local=0'
                resp = await AsyncFetcher.fetch_all([current_url], headers=headers, proxy=self.proxy)
                self.results = resp[0]
                self.totalresults += self.results
                # if 'Results from Microsoft Bing.' in resp[0] \
                if 'Not many great matches came back for your search' in resp[0] \
                        or 'Your request has been flagged as being suspicious and Brave Search' in resp[0] \
                        or 'Prove' in resp[0] and 'robot' in resp[0] or 'Robot' in resp[0]:
                    # print('Breaking!')
                    break
                await asyncio.sleep(get_delay() + 5)
        except Exception as e:
            print(f'An exception has occurred in bravesearch: {e}')

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
