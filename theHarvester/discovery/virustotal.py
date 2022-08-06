from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from pprint import pprint


class SearchVirustotal:

    def __init__(self, word):
        self.word = word
        self.key = Core.virustotal_key()
        if self.key is None:
            raise MissingKey('virustotal')
        self.totalhosts = set
        self.proxy = False

    async def do_search(self):
        url = f'https://www.virustotal.com/api/v3/domains/{self.word}/subdomains?limit=40'
        response = await AsyncFetcher.fetch_all([url], json=True, headers={'User-Agent': Core.get_user_agent(),
                                                                           'X-APIKEY': self.key},
                                                proxy=self.proxy)
        entry = [host for host in response]
        pprint(entry.items())

    # async def get_hostnames(self) -> set:
    #     return self.total_results

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()