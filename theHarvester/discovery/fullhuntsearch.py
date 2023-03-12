from theHarvester.discovery.constants import *
from theHarvester.lib.core import *


class SearchFullHunt:

    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.fullhunt_key()
        if self.key is None:
            raise MissingKey('fullhunt')
        self.total_results = None
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://fullhunt.io/api/v1/domain/{self.word}/subdomains'
        response = await AsyncFetcher.fetch_all([url], json=True, headers={'User-Agent': Core.get_user_agent(),
                                                                           'X-API-KEY': self.key},
                                                proxy=self.proxy)
        self.total_results = response[0]['hosts']

    async def get_hostnames(self):
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
