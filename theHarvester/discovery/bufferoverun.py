from theHarvester.lib.core import *
import re


class SearchBufferover:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.proxy = False

    async def do_search(self):
        url = f'https://dns.bufferover.run/dns?q={self.word}'
        responses = await AsyncFetcher.fetch_all(urls=[url], json=True, proxy=self.proxy)
        responses = responses[0]
        dct = responses

        if dct['FDNS_A']:
            self.totalhosts: set = {
                host.split(',')[0].replace('www.', '') if ',' in host and self.word.replace('www.', '') in host.split(',')[
                    0] in host else
                host.split(',')[1] for host in dct['FDNS_A']}

        self.totalips: set = {ip.split(',')[0] for ip in dct['FDNS_A'] if
                              re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip.split(',')[0])}

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
