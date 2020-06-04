from typing import Type
from theHarvester.lib.core import *


class SearchThreatminer:

    def __init__(self, word):
        self.word = word
        self.totalhosts = list
        self.proxy = False

    async def do_search(self):
        url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=5'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts: set = {host for host in response[0]['results']}

    async def get_hostnames(self) -> Type[list]:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
