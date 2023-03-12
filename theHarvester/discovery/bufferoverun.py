import re
from theHarvester.lib.core import *
from theHarvester.discovery.constants import MissingKey
from typing import Set


class SearchBufferover:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: Set = set()
        self.totalips: Set = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        response = await AsyncFetcher.fetch_all([url], json=True, headers={'User-Agent': Core.get_user_agent(),
                                                                           'x-api-key': f'{self.key}'}, proxy=self.proxy)
        dct = response[0]
        if dct['Results']:
            self.totalhosts = {
                host.split(',')if ',' in host and self.word.replace('www.', '') in host.split(',')[0] in host else
                host.split(',')[4] for host in dct['Results']}

        self.totalips = {ip.split(',')[0] for ip in dct['Results'] if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip.split(',')[0])}

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
