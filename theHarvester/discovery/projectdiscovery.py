from theHarvester.discovery.constants import *
from theHarvester.lib.core import *


class SearchDiscovery:

    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.projectdiscovery_key()
        if self.key is None:
            raise MissingKey('ProjectDiscovery')
        self.total_results = None
        self.proxy = False

    async def do_search(self):
        url = f'https://dns.projectdiscovery.io/dns/{self.word}/subdomains'
        response = await AsyncFetcher.fetch_all([url], json=True, headers={'User-Agent': Core.get_user_agent(),
                                                                           'Authorization': self.key},
                                                proxy=self.proxy)
        self.total_results = [f'{domains}.{self.word}' for domains in response[0]['subdomains']]

    async def get_hostnames(self):
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
