from typing import List, Set
from theHarvester.lib.core import *


class SearchUrlscan:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: Set = set()
        self.totalips: Set = set()
        self.interestingurls: Set = set()
        self.totalasns: Set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://urlscan.io/api/v1/search/?q=domain:{self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        resp = response[0]
        self.totalhosts = {f"{page['page']['domain']}" for page in resp['results']}
        self.totalips = {f"{page['page']['ip']}" for page in resp['results'] if 'ip' in page['page'].keys()}
        self.interestingurls = {f"{page['page']['url']}" for page in resp['results'] if self.word in page['page']['url'] and 'url' in page['page'].keys()}
        self.totalasns = {f"{page['page']['asn']}" for page in resp['results'] if 'asn' in page['page'].keys()}

    async def get_hostnames(self) -> Set:
        return self.totalhosts

    async def get_ips(self) -> Set:
        return self.totalips

    async def get_interestingurls(self) -> Set:
        return self.interestingurls

    async def get_asns(self) -> Set:
        return self.totalasns

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
