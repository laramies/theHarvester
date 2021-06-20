from typing import Type
from theHarvester.lib.core import *


class SearchAnubis:

    def __init__(self, word):
        self.word = word
        self.totalhosts = list
        self.proxy = False

    async def do_search(self):
        url = f'https://jldc.me/anubis/subdomains/{self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts: list = response[0]

    async def get_hostnames(self) -> Type[list]:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
