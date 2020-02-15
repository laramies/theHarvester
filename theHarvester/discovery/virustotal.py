from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import re


class SearchVirustotal:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.quantity = '100'
        self.counter = 0
        self.proxy = False

    async def do_search(self):
        base_url = f'https://www.virustotal.com/ui/domains/{self.word}/subdomains?relationships=resolutions&cursor=STMwCi4%3D&limit=40'
        headers = {'User-Agent': Core.get_user_agent()}
        responses = await AsyncFetcher.fetch_all([base_url], headers=headers, proxy=self.proxy)
        self.results = responses[0]
        self.totalresults += self.results

    async def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        new_lst = []
        for host in await rawres.hostnames():
            host = str(host)
            if host[0].isdigit():
                matches = re.match('.+([0-9])[^0-9]*$', host)
                # Get last digit of string and shift hostname to remove ip in string
                new_lst.append(host[matches.start(1) + 1:])
            else:
                new_lst.append(host)
        return new_lst

    async def process(self, proxy=False):
        self.proxy = proxy
        print('\tSearching results.')
        await self.do_search()
