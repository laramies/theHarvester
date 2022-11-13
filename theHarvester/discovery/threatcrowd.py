from typing import List, Set
from theHarvester.lib.core import *


class SearchThreatcrowd:

    def __init__(self, word) -> None:
        self.word = word.replace(' ', '%20')
        self.hostnames: List = list()
        self.ips: Set = set()
        self.proxy = False

    async def do_search(self) -> None:
        base_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            responses = await AsyncFetcher.fetch_all([base_url], headers=headers, proxy=self.proxy, json=True)
            resp = responses[0]
            self.ips = {ip['ip_address'] for ip in resp['resolutions'] if len(ip['ip_address']) > 4}
            self.hostnames = list(resp['subdomains'])
        except Exception as e:
            print(e)

    async def get_ips(self) -> Set:
        return self.ips

    async def get_hostnames(self) -> List:
        return self.hostnames

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        await self.get_hostnames()
