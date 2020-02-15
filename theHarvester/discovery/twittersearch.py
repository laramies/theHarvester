from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import re


class SearchTwitter:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = int(limit)
        self.counter = 0
        self.proxy = False

    async def do_search(self):
        base_url = f'https://{self.server}/search?num=100&start=xx&hl=en&meta=&q=site%3Atwitter.com%20intitle%3A%22on+Twitter%22%20{self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
            for url in urls:
                response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
                self.results = response[0]
                if await search(self.results):
                    try:
                        self.results = await google_workaround(url)
                        if isinstance(self.results, bool):
                            print('Google is blocking your ip and the workaround, returning')
                            return
                    except Exception:
                        # google blocked, no useful result
                        return
                self.totalresults += self.results
        except Exception as error:
            print(error)

    async def get_people(self, proxy=False):
        self.proxy = proxy
        rawres = myparser.Parser(self.totalresults, self.word)
        to_parse = await rawres.people_twitter()
        # fix invalid handles that look like @user other_output
        handles = set()
        for handle in to_parse:
            result = re.search(r'^@?(\w){1,15}', handle)
            if result:
                handles.add(result.group(0))
        return handles

    async def process(self):
        await self.do_search()
