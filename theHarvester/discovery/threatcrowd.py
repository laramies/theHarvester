from typing import List
from theHarvester.lib.core import *


class SearchThreatcrowd:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.hostnames = list()
        self.ips = list()
        self.proxy = False

    async def do_search(self):
        base_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            responses = await AsyncFetcher.fetch_all([base_url], headers=headers, proxy=self.proxy, json=True)
            resp = responses[0]
            self.ips = {ip['ip_address'] for ip in resp['resolutions'] if len(ip['ip_address']) > 4}
            self.hostnames = set(list(resp['subdomains']))
        except Exception as e:
            print(e)

    async def get_ips(self) -> List:
        return self.ips

    async def get_hostnames(self) -> List:
        return self.hostnames

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        await self.get_hostnames()
