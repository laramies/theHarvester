import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchHaveIBeenPwned:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.haveibeenpwned_key()
        if self.api_key is None:
            raise MissingKey('HaveIBeenPwned')
        self.base_url = 'https://haveibeenpwned.com/api/v3'
        self.headers = {'hibp-api-key': self.api_key, 'user-agent': 'theHarvester', 'Content-Type': 'application/json'}
        self.hosts: set[str] = set()
        self.emails: set[str] = set()
        self.breaches: list[dict] = []
        self.pastes: list[dict] = []
        self.breach_dates: set[str] = set()
        self.breach_types: set[str] = set()
        self.affected_data: set[str] = set()

    async def process(self, proxy: bool = False) -> None:
        """Search for breaches associated with a domain or email."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None, url=f'{self.base_url}/breaches?domain={self.word}', headers=self.headers, proxy=proxy
                )
                if response:
                    self.breaches = response
                    self._extract_data()
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f'{self.base_url}/breaches?domain={self.word}') as response:
                        if response.status == 200:
                            self.breaches = await response.json()
                            self._extract_data()
        except Exception as e:
            print(f'Error in HaveIBeenPwned search: {e}')

    def _extract_data(self) -> None:
        """Extract and categorize breach information."""
        for breach in self.breaches:
            if 'Domain' in breach:
                self.hosts.add(breach['Domain'])
            if 'BreachDate' in breach:
                self.breach_dates.add(breach['BreachDate'])
            if 'BreachType' in breach:
                self.breach_types.add(breach['BreachType'])
            if 'DataClasses' in breach:
                self.affected_data.update(breach['DataClasses'])

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_breaches(self) -> list[dict]:
        return self.breaches

    async def get_pastes(self) -> list[dict]:
        return self.pastes

    async def get_breach_dates(self) -> set[str]:
        return self.breach_dates

    async def get_breach_types(self) -> set[str]:
        return self.breach_types

    async def get_affected_data(self) -> set[str]:
        return self.affected_data
