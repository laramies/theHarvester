from typing import Type, List, Set
from theHarvester.lib.core import *


class SearchThreatminer:

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: Set = set()
        self.totalips: Set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=5'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        self.totalhosts = {host for host in response[0]['results']}
        second_url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=2'
        secondresp = await AsyncFetcher.fetch_all([second_url], json=True, proxy=self.proxy)
        try:
            self.totalips = {resp['ip'] for resp in secondresp[0]['results']}
        except TypeError:
            pass

    async def get_hostnames(self) -> Set:
        return self.totalhosts

    async def get_ips(self) -> Set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
