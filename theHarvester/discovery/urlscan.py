from typing import List
from theHarvester.lib.core import *


class SearchUrlscan:
    def __init__(self, word):
        self.word = word
        self.totalhosts = list()
        self.totalips = list()
        self.interestingurls = list()
        self.totalasns = list()
        self.proxy = False

    async def do_search(self):
        url = f'https://urlscan.io/api/v1/search/?q=domain:{self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        resp = response[0]
        self.totalhosts = {f"{page['page']['domain']}" for page in resp['results']}
        self.totalips = {f"{page['page']['ip']}" for page in resp['results'] if 'ip' in page['page'].keys()}
        self.interestingurls = {f"{page['page']['url']}" for page in resp['results'] if self.word in page['page']['url'] and 'url' in page['page'].keys()}
        self.totalasns = {f"{page['page']['asn']}" for page in resp['results'] if 'asn' in page['page'].keys()}

    async def get_hostnames(self) -> List:
        return self.totalhosts

    async def get_ips(self) -> List:
        return self.totalips

    async def get_interestingurls(self) -> List:
        return self.interestingurls

    async def get_asns(self) -> List:
        return self.totalasns

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
