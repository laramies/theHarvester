from theHarvester.lib.core import *
from bs4 import BeautifulSoup
import asyncio


class SearchSuip:

    def __init__(self, word: str):
        self.word: str = word
        self.results: str = ''
        self.totalresults: str = ''
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def request(self, url, params, findomain=False):
        headers = {'User-Agent': Core.get_user_agent()}
        data = {'url': self.word.replace('www.', ''), 'only_resolved': '1', 'Submit1': 'Submit'} if findomain else \
            {'url': self.word.replace('www.', ''), 'Submit1': 'Submit'}
        return await AsyncFetcher.post_fetch(url, headers=headers, params=params, data=data, proxy=self.proxy)

    async def handler(self, url):
        first_param = [url, (('act', 'subfinder'),), False]
        second_param = [url, (('act', 'amass'),), False]
        third_param = [url, (('act', 'findomain'),), True]
        async_requests = [
            self.request(url=url, params=params, findomain=findomain)
            for url, params, findomain in [first_param, second_param, third_param]
        ]
        results = await asyncio.gather(*async_requests)
        return results

    async def do_search(self):
        try:
            results = await self.handler(url="https://suip.biz/")
            for num in range(len(results)):
                # iterate through results and parse out the urls
                result = results[num]
                soup = BeautifulSoup(str(result), 'html.parser')
                hosts: list = str(soup.find('pre')).splitlines() if num != 2 else \
                    [line for line in str(soup.find('pre')).splitlines() if 'A total of' not in line]
                # The last iteration is special because findomain throws in some more lines that we need to filter out
                await self.clean_hosts(hosts)
        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        print('\tSearching results.')

    async def clean_hosts(self, soup_hosts):
        for host in soup_hosts:
            host = str(host).strip()
            if len(host) > 1 and self.word.replace('www.', '') in host:
                self.totalhosts.add(host[1:] if host[0] == '.' else host)
