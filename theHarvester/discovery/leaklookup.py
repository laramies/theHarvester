import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchLeakLookup:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.leaklookup_key()
        self.base_url = 'https://leak-lookup.com/api'
        self.headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        self.hosts: set[str] = set()
        self.emails: set[str] = set()
        self.leaks: list[dict] = []
        self.passwords: set[str] = set()
        self.sources: set[str] = set()
        self.leak_dates: set[str] = set()

    async def process(self, proxy: bool = False) -> None:
        """Search for leaked credentials associated with an email."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None,
                    url=f'{self.base_url}/search?key={self.api_key}&type=email&query={self.word}',
                    headers=self.headers,
                    proxy=proxy,
                )
                if response:
                    self.leaks = response
                    self._extract_data()
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f'{self.base_url}/search?key={self.api_key}&type=email&query={self.word}') as response:
                        if response.status == 200:
                            self.leaks = await response.json()
                            self._extract_data()
                        elif response.status == 401:
                            print('[!] Missing API key for Leak-Lookup.')
                            raise MissingKey('Leak-Lookup')
        except Exception as e:
            print(f'Error in Leak-Lookup search: {e}')

    def _extract_data(self) -> None:
        """Extract and categorize leak information."""
        for leak in self.leaks:
            if 'domain' in leak:
                self.hosts.add(leak['domain'])
            if 'email' in leak:
                self.emails.add(leak['email'])
            if 'password' in leak:
                self.passwords.add(leak['password'])
            if 'source' in leak:
                self.sources.add(leak['source'])
            if 'date' in leak:
                self.leak_dates.add(leak['date'])

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_leaks(self) -> list[dict]:
        return self.leaks

    async def get_passwords(self) -> set[str]:
        return self.passwords

    async def get_sources(self) -> set[str]:
        return self.sources

    async def get_leak_dates(self) -> set[str]:
        return self.leak_dates
