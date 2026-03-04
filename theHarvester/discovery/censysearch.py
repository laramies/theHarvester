from math import ceil

from censys.common import __version__
from censys.common.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
)
from censys.search import CensysCerts

from theHarvester import __version__ as thehavester_version
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core


class SearchCensys:
    MAX_RESULTS_PER_PAGE = 100

    def __init__(self, domain, limit: int = 500) -> None:
        self.word = domain
        self.key = Core.censys_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey('Censys ID and/or Secret')
        self.totalhosts: set[str] = set()
        self.emails: set[str] = set()
        self.limit = limit
        self.proxy = False

    @staticmethod
    def _normalize_emails(email_address: object) -> set[str]:
        if isinstance(email_address, str):
            return {email_address}
        if isinstance(email_address, list):
            return {email for email in email_address if isinstance(email, str)}
        return set()

    async def do_search(self) -> None:
        try:
            cert_search = CensysCerts(
                api_id=self.key[0],
                api_secret=self.key[1],
                user_agent=f'censys-python/{__version__} (theHarvester/{thehavester_version}); +https://github.com/laramies/theHarvester)',
            )
        except CensysUnauthorizedException:
            raise MissingKey('Censys ID and/or Secret')

        if self.limit <= 0:
            return

        query = f'names: {self.word}'
        try:
            response = cert_search.search(
                query=query,
                per_page=min(self.limit, self.MAX_RESULTS_PER_PAGE),
                pages=ceil(self.limit / self.MAX_RESULTS_PER_PAGE),
                fields=['names', 'parsed.subject.email_address'],
            )
            records_seen = 0
            for cert_page in response:
                for cert in cert_page:
                    if records_seen >= self.limit:
                        return
                    self.totalhosts.update(cert.get('names', []))
                    email_address = cert.get('parsed', {}).get('subject', {}).get('email_address')
                    self.emails.update(self._normalize_emails(email_address))
                    records_seen += 1
        except CensysRateLimitExceededException:
            print('Censys rate limit exceeded')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.emails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
