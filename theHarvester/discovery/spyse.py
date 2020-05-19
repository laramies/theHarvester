from theHarvester.discovery.constants import *
from theHarvester.lib.core import *


class SearchSpyse:

    def __init__(self, word):
        self.ips = set()
        self.word = word
        self.key = Core.spyse_key()
        if self.key is None:
            raise MissingKey(True)
        self.results = ''
        self.hosts = set()
        self.proxy = False

    async def do_search(self):
        try:
            headers = {
                'accept': 'application/json',
                'Authorization': f'Bearer {self.key}',
            }
            base_url = f'https://api.spyse.com/v2/data/domain/subdomain?limit=100&domain={self.word}'
            results = await AsyncFetcher.fetch_all([base_url], json=True, proxy=self.proxy, headers=headers)
            results = results[0]
            self.hosts = {domain['name'] for domain in results['data']['items']}
        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_hostnames(self):
        return self.hosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
