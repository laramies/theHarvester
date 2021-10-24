from theHarvester.lib.core import *


class SearchN45ht:

    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.proxy = False

    async def do_search(self):
        url = f'https://api.n45ht.or.id/v1/subdomain-enumeration?domain={self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        responses = response[0]
        dct = responses
        self.totalhosts: set = {host for host in dct['subdomains']}

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
