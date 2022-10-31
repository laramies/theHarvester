from typing import Type
from theHarvester.lib.core import *


class SearchAnubis:

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: List = []
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://jldc.me/anubis/subdomains/{self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts = response[0]

    async def get_hostnames(self) -> List:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
