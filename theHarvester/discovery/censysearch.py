from censys.common import __version__
from censys.common.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
)
from censys.search import CensysCerts

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from theHarvester.lib.version import version as thehavester_version


class SearchCensys:
    def __init__(self, domain, limit: int = 500) -> None:
        self.word = domain
        self.key = Core.censys_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey('Censys ID and/or Secret')
        self.totalhosts: set = set()
        self.emails: set = set()
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> None:
        try:
            cert_search = CensysCerts(
                api_id=self.key[0],
                api_secret=self.key[1],
                user_agent=f'censys-python/{__version__} (theHarvester/{thehavester_version}); +https://github.com/laramies/theHarvester)',
            )
        except CensysUnauthorizedException:
            raise MissingKey('Censys ID and/or Secret')

        query = f'names: {self.word}'
        try:
            response = cert_search.search(
                query=query,
                fields=['names', 'parsed.subject.email_address'],
                max_records=self.limit,
            )
            for cert in response():
                self.totalhosts.update(cert.get('names', []))
                email_address = cert.get('parsed', {}).get('subject', {}).get('email_address', [])
                self.emails.update(email_address)
        except CensysRateLimitExceededException:
            print('Censys rate limit exceeded')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.emails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
