from typing import Type
from theHarvester.lib.core import *


class SearchUrlscan:

    def __init__(self, word):
        self.word = word
        self.totalhosts = list
        self.proxy = False

    async def do_search(self):
        url = f'https://urlscan.io/api/v1/search/?q=domain:{self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts: set = {host['domain'] for host in response[0]}
        print(self.totalhosts)

    # async def get_hostnames(self) -> Type[list]:
    #     return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
