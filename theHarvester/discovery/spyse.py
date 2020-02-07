from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from typing import Dict


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
            base_url = f'https://api.spyse.com/v1/subdomains-aggregate?api_token={self.key}&domain={self.word}'
            response = await AsyncFetcher.fetch_all([base_url], json=True, proxy=self.proxy)
            self.results: Dict = response[0]
            ips = self.results['data']['ip']
            self.ips = {ip['entity']['value'] for ip in [value for value in ips['results']]}

            cidr = self.results['cidr']
            cidr16_domains = {true_domain[0] if isinstance(true_domain, list) else true_domain for true_domain in
                              [domain for domain in
                               [data['data']['domains'] for data in [result for result in cidr['cidr16']['results']]]]}
            cidr24_domains = {true_domain[0] if isinstance(true_domain, list) else true_domain for true_domain in
                              [domain for domain in
                               [data['data']['domains'] for data in
                                [result for result in cidr['cidr24']['results']]]]}

            self.hosts.update(cidr16_domains | cidr24_domains)
        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_hostnames(self):
        return self.hosts

    async def get_ips(self):
        return self.ips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
        print('\tSearching results.')

    async def process(self):
        await self.do_search()
