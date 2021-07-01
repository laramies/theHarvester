from theHarvester.lib.core import *
import re


class SearchOmnisint:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.limit = 10000
        self.proxy = False

    async def do_search(self):
        base_url = f'https://sonar.omnisint.io/all/{self.word}?page=xx'
        urls = [base_url.replace('xx', str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, json=True, headers={'User-Agent': Core.get_user_agent()}, proxy=self.proxy)
        for response in responses:
            try:
                for entry in response:
                    for key, value in entry.items():
                        if key == 'null' or value == 'null':
                            break
                        if key == 'name':
                            self.totalhosts.add(value)
                        if key == 'value' and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                            self.totalips.add(value)
            except Exception:
                # Break on 'NoneType' object is not iterable to allow data to be parsed
                break

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
