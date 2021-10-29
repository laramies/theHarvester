from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from censys.search import CensysCertificates
from censys.common import __version__
from censys.common.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
)


class SearchCensys:
    def __init__(self, domain, limit=500):
        self.word = domain
        self.key = Core.censys_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey("Censys ID and/or Secret")
        self.totalhosts = set()
        self.emails = set()
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        try:
            cert_search = CensysCertificates(
                api_id=self.key[0],
                api_secret=self.key[1],
                user_agent=f"censys/{__version__} (theHarvester/{Core.version()}; +https://github.com/laramies/theHarvester)",
            )
        except CensysUnauthorizedException:
            raise MissingKey('Censys ID and/or Secret')

        query = f"parsed.names: {self.word}"
        try:
            response = cert_search.search(
                query=query,
                fields=["parsed.names", "metadata", "parsed.subject.email_address"],
                max_records=self.limit,
            )
            for cert in response:
                self.totalhosts.update(cert.get("parsed.names", []))
                self.emails.update(cert.get("parsed.subject.email_address", []))
        except CensysRateLimitExceededException:
            print("Censys rate limit exceeded")

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.emails

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
