from theHarvester.lib.core import *
import re


class SearchOmnisint:

    def __init__(self, word, limit):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        base_url = f'https://sonar.omnisint.io/all/{self.word}?page=xx'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
        response = await AsyncFetcher.fetch_all([urls], json=True, headers={'User-Agent': Core.get_user_agent()},
                                                proxy=self.proxy)
        for entry in response[0]:
            if 'null' in entry:
                break
            else:
                self.totalhosts.update({host['name'] for host in entry})
                self.totalips.update({ip['value'] for ip in entry
                                      if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip['value'])})

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
