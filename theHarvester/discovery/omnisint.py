from theHarvester.lib.core import *


class SearchOmnisint:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.proxy = False

    async def do_search(self):
        base_url = f'https://sonar.omnisint.io/all/{self.word}?page=1'
        responses = await AsyncFetcher.fetch_all([base_url], json=True, headers={'User-Agent': Core.get_user_agent()},
                                                 proxy=self.proxy)
        self.totalhosts = list({host for host in responses[0]})

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
