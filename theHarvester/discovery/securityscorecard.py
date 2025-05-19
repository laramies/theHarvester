import aiohttp
from typing import Dict, List, Set
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core, AsyncFetcher

class SearchSecurityScorecard:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.securityscorecard_key()
        self.base_url = "https://api.securityscorecard.io"
        self.headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json"
        }
        self.hosts = set()
        self.score = 0
        self.grades = {}
        self.issues = []
        self.recommendations = []
        self.history = []

    async def process(self, proxy: bool = False) -> None:
        """Get security scorecard information for a domain."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None,
                    url=f"{self.base_url}/companies/{self.word}",
                    headers=self.headers,
                    proxy=proxy
                )
                if response:
                    self._extract_data(response)
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f"{self.base_url}/companies/{self.word}") as response:
                        if response.status == 200:
                            data = await response.json()
                            self._extract_data(data)
                        elif response.status == 401:
                            print("[!] Missing API key for SecurityScorecard.")
                            raise MissingKey("SecurityScorecard")
        except Exception as e:
            print(f"Error in SecurityScorecard search: {e}")

    def _extract_data(self, data: Dict) -> None:
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

    async def get_hostnames(self) -> Set[str]:
        return self.hosts

    async def get_score(self) -> int:
        return self.score

    async def get_grades(self) -> Dict:
        return self.grades

    async def get_issues(self) -> List[Dict]:
        return self.issues

    async def get_recommendations(self) -> List[Dict]:
        return self.recommendations

    async def get_history(self) -> List[Dict]:
        return self.history 