import asyncio
from typing import Any

from theHarvester.discovery.builtwith import SearchBuiltWith
from theHarvester.discovery.haveibeenpwned import SearchHaveIBeenPwned
from theHarvester.discovery.leaklookup import SearchLeakLookup
from theHarvester.discovery.securityscorecard import SearchSecurityScorecard


class AdditionalAPIs:
    """Wrapper class for additional API services."""

    def __init__(self, domain: str, api_keys: dict[str, str] | None = None):
        self.domain = domain
        self.api_keys = api_keys or {}

        # Initialize API services
        self.haveibeenpwned = SearchHaveIBeenPwned(domain)
        self.leaklookup = SearchLeakLookup(domain)
        self.securityscorecard = SearchSecurityScorecard(domain)
        self.builtwith = SearchBuiltWith(domain)

        # Results storage
        self.results = {'breaches': [], 'leaks': [], 'security_score': {}, 'tech_stack': {}, 'hosts': set(), 'emails': set()}

    async def process(self, proxy: bool = False) -> dict[str, Any]:
        """Process all additional API services and return combined results."""
        tasks = [
            self._process_haveibeenpwned(proxy),
            self._process_leaklookup(proxy),
            self._process_securityscorecard(proxy),
            self._process_builtwith(proxy),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Convert sets to lists for JSON serialization
        self.results['hosts'] = list(self.results['hosts'])
        self.results['emails'] = list(self.results['emails'])

        return self.results

    async def _process_haveibeenpwned(self, proxy: bool = False):
        """Process HaveIBeenPwned API."""
        try:
            await self.haveibeenpwned.process(proxy)
            self.results['breaches'] = self.haveibeenpwned.breaches
            self.results['hosts'].update(self.haveibeenpwned.hosts)
            self.results['emails'].update(self.haveibeenpwned.emails)
        except Exception as e:
            print(f'Error processing HaveIBeenPwned: {e}')

    async def _process_leaklookup(self, proxy: bool = False):
        """Process Leak-Lookup API."""
        try:
            await self.leaklookup.process(proxy)
            self.results['leaks'] = self.leaklookup.leaks
            self.results['hosts'].update(self.leaklookup.hosts)
            self.results['emails'].update(self.leaklookup.emails)
        except Exception as e:
            print(f'Error processing Leak-Lookup: {e}')

    async def _process_securityscorecard(self, proxy: bool = False):
        """Process SecurityScorecard API."""
        try:
            await self.securityscorecard.process(proxy)
            self.results['security_score'] = {
                'score': self.securityscorecard.score,
                'grades': self.securityscorecard.grades,
                'issues': self.securityscorecard.issues,
                'recommendations': self.securityscorecard.recommendations,
            }
            self.results['hosts'].update(self.securityscorecard.hosts)
        except Exception as e:
            print(f'Error processing SecurityScorecard: {e}')

    async def _process_builtwith(self, proxy: bool = False):
        """Process BuiltWith API."""
        try:
            await self.builtwith.process(proxy)
            self.results['tech_stack'] = {
                'frameworks': list(self.builtwith.frameworks),
                'languages': list(self.builtwith.languages),
                'servers': list(self.builtwith.servers),
                'cms': list(self.builtwith.cms),
                'analytics': list(self.builtwith.analytics),
                'interesting_urls': list(self.builtwith.interesting_urls),
            }
            self.results['hosts'].update(self.builtwith.hosts)
        except Exception as e:
            print(f'Error processing BuiltWith: {e}')

    async def get_hosts(self) -> set:
        """Get all discovered hosts."""
        return self.results['hosts']

    async def get_emails(self) -> set:
        """Get all discovered emails."""
        return self.results['emails']
