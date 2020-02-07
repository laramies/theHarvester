from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import re
import asyncio


class SearchExalead:

    def __init__(self, word, limit, start):
        self.word = word
        self.files = 'pdf'
        self.results = ""
        self.total_results = ""
        self.server = 'www.exalead.com'
        self.hostname = 'www.exalead.com'
        self.limit = limit
        self.counter = start
        self.proxy = False

    async def do_search(self):
        base_url = f'https://{self.server}/search/web/results/?q=%40{self.word}&elements_per_page=50&start_index=xx'
        headers = {
            'Host': self.hostname,
            'Referer': ('http://' + self.hostname + '/search/web/results/?q=%40' + self.word),
            'User-agent': Core.get_user_agent()
        }
        urls = [base_url.replace("xx", str(num)) for num in range(self.counter, self.limit, 50) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response

    async def do_search_files(self, files):
        url = f'https://{self.server}/search/web/results/?q=%40{self.word}filetype:{self.files}&elements_per_page' \
              f'=50&start_index={self.counter} '
        headers = {
            'Host': self.hostname,
            'Referer': ('http://' + self.hostname + '/search/web/results/?q=%40' + self.word),
            'User-agent': Core.get_user_agent()
        }
        responses = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        self.results = responses[0]
        self.total_results += self.results

    async def check_next(self):
        renext = re.compile('topNextUrl')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = '1'
            print(str(self.counter))
        else:
            nexty = '0'
        return nexty

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()

    async def get_files(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.fileurls(self.files)

    async def process(self, proxy=False):
        self.proxy = proxy
        print('Searching results')
        await self.do_search()

    async def process_files(self, files):
        while self.counter < self.limit:
            await self.do_search_files(files)
            more = self.check_next()
            await asyncio.sleep(2)
            if more == '1':
                self.counter += 50
            else:
                break
