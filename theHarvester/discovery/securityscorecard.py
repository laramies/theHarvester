import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchSecurityScorecard:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.securityscorecard_key()
        if self.api_key is None:
            raise MissingKey('SecurityScorecard')
        self.base_url = 'https://api.securityscorecard.io'
        self.headers = {'Authorization': f'Token {self.api_key}', 'Content-Type': 'application/json'}
        self.hosts: set[str] = set()
        self.score: int = 0
        self.grades: dict = {}
        self.issues: list[dict] = []
        self.recommendations: list[dict] = []
        self.history: list[dict] = []
        self.ips: list[str] = []

    async def process(self, proxy: bool = False) -> None:
        """Get security scorecard information for a domain."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None, url=f'{self.base_url}/companies/{self.word}', headers=self.headers, proxy=proxy
                )
                if response:
                    self._extract_data(response)
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f'{self.base_url}/companies/{self.word}') as response:
                        if response.status == 200:
                            data = await response.json()
                            self._extract_data(data)
        except Exception as e:
            print(f'Error in SecurityScorecard search: {e}')

    def _extract_data(self, data: dict) -> None:
        """Extract and categorize security scorecard information."""
        if 'grade' in data:
            self.score = data.get('grade', 0)

        if 'factor_grades' in data:
            self.grades = data['factor_grades']

        if 'issues' in data:
            self.issues = data['issues']

        if 'recommendations' in data:
            self.recommendations = data['recommendations']

        if 'history' in data:
            self.history = data['history']

        if 'domains' in data:
            self.hosts.update(data['domains'])

        # Some responses may include IP addresses under different keys
        ips = []
        if isinstance(data.get('ips'), list):
            ips = [str(ip) for ip in data.get('ips', []) if isinstance(ip, str | int)]
        elif isinstance(data.get('ip_addresses'), list):
            ips = [str(ip) for ip in data.get('ip_addresses', []) if isinstance(ip, str | int)]
        elif isinstance(data.get('associated_ips'), list):
            ips = [str(ip) for ip in data.get('associated_ips', []) if isinstance(ip, str | int)]
        if ips:
            # Deduplicate while preserving already stored entries
            self.ips = list({*self.ips, *ips})

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_ips(self) -> list[str]:
        return self.ips

    async def get_score(self) -> int:
        return self.score

    async def get_grades(self) -> dict:
        return self.grades

    async def get_issues(self) -> list[dict]:
        return self.issues

    async def get_recommendations(self) -> list[dict]:
        return self.recommendations

    async def get_history(self) -> list[dict]:
        return self.history
