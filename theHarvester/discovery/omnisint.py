from theHarvester.lib.core import *
import re


class SearchOmnisint:

    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.proxy = False

    async def do_search(self):
        url = f'https://sonar.omnisint.io/all/{self.word}?page=0'
        response = await AsyncFetcher.fetch_all([url], json=True, headers={'User-Agent': Core.get_user_agent()},
                                                proxy=self.proxy)

        self.totalhosts: set = {host['name'] for host in response[0]}
        self.totalips: set = {ip['value'] for ip in response[0]
                              if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip['value'])}

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
