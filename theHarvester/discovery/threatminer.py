from typing import Type
from theHarvester.lib.core import *


class SearchThreatminer:

    def __init__(self, word):
        self.word = word
        self.totalhosts = list
        self.totalips = list
        self.proxy = False

    async def do_search(self):
        url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=5'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts: set = {host for host in response[0]['results']}
        second_url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=2'
        secondresp = await AsyncFetcher.fetch_all([second_url], json=True, proxy=self.proxy)
        try:
            self.totalips: set = {resp['ip'] for resp in secondresp[0]['results']}
        except TypeError:
            pass

    async def get_hostnames(self) -> Type[list]:
        return self.totalhosts

    async def get_ips(self) -> Type[list]:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
