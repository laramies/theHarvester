from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from censys.certificates import CensysCertificates
from censys.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
)


class SearchCensys:
    def __init__(self, domain):
        self.word = domain
        self.key = Core.censys_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey("Censys ID and/or Secret")
        self.totalhosts = set()
        self.proxy = False

    async def do_search(self):
        try:
            c = CensysCertificates(api_id=self.key[0], api_secret=self.key[1])
        except CensysUnauthorizedException:
            raise MissingKey("Censys ID and/or Secret")

        query = f"parsed.names: {self.word}"
        try:
            response = c.search(query=query, fields=["parsed.names", "metadata"])
            for cert in response:
                self.totalhosts.update(cert["parsed.names"])
        except CensysRateLimitExceededException:
            print("Censys rate limit exceeded")

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
