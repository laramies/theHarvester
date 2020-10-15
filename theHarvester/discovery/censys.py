from pprint import pprint

from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
import censys.certificates
import censys.base


class SearchCensys:

    def __init__(self, word):
        self.word = word
        self.key = Core.censys_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey(True, 'Censys ID or Secret')
        self.totalhosts = set()
        self.proxy = False

    async def do_search(self):
        cert = censys.certificates.CensysCertificates(api_id=self.key[0], api_secret=self.key[1])
        query = f'parsed.names: {self.word}'
        try:
            response = cert.search(query=query, fields=['parsed.names'])
        except censys.base.CensysRateLimitExceededException:
            print('Censys rate limit exceeded')
        for hosts in response:
            pprint(set(hosts['parsed.names']))
            self.totalhosts.update(hosts['parsed.names'])

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
