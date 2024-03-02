import asyncio

import ujson
from bs4 import BeautifulSoup

from theHarvester.discovery.constants import get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchSubdomainfinderc99:
    def __init__(self, word) -> None:
        self.word = word
        self.total_results: set = set()
        self.proxy = False
        # TODO add api support
        self.server = 'https://subdomainfinder.c99.nl/'
        self.totalresults = ''

    async def do_search(self) -> None:
        # Based on https://gist.github.com/th3gundy/bc83580cbe04031e9164362b33600962
        headers = {'User-Agent': Core.get_user_agent()}
        resp = await AsyncFetcher.fetch_all([self.server], headers=headers, proxy=self.proxy)
        data = await self.get_csrf_params(resp[0])

        data['scan_subdomains'] = ''
        data['domain'] = self.word
        data['privatequery'] = 'on'
        await asyncio.sleep(get_delay())
        second_resp = await AsyncFetcher.post_fetch(self.server, headers=headers, proxy=self.proxy, data=ujson.dumps(data))

        # print(second_resp)
        self.totalresults += second_resp
        # y = await self.get_hostnames()
        # print(list(sorted(y)))
        # print(f'Found: {len(y)} subdomains')

        # regex = r"value='(https://subdomainfinder\.c99\.nl/scans/\d{4}-\d{2}-\d{2}/" + self.word + r")'"
        # match = re.search(regex, second_resp)
        # if match:
        #     print(match.group(1))

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    @staticmethod
    async def get_csrf_params(data):
        csrf_params = {}
        html = BeautifulSoup(data, 'html.parser').find('div', {'class': 'input-group'})
        for c in html.find_all('input'):
            try:
                csrf_params[c.get('name')] = c.get('value')
            except Exception:
                continue

        return csrf_params
