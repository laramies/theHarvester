import aiohttp
from typing import Dict, Set, List
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core, AsyncFetcher

class SearchBuiltWith:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.builtwith_key()
        self.base_url = "https://api.builtwith.com/v21/api.json"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.hosts = set()
        self.tech_stack = {}
        self.interesting_urls = set()
        self.frameworks = set()
        self.languages = set()
        self.servers = set()
        self.cms = set()
        self.analytics = set()

    async def process(self, proxy: bool = False) -> None:
        """Get technology stack information for a domain."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None,
                    url=f"{self.base_url}?KEY={self.api_key}&LOOKUP={self.word}",
                    headers=self.headers,
                    proxy=proxy
                )
                if response:
                    self.tech_stack = response
                    self._extract_data()
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f"{self.base_url}?KEY={self.api_key}&LOOKUP={self.word}") as response:
                        if response.status == 200:
                            data = await response.json()
                            self.tech_stack = data
                            self._extract_data()
                        elif response.status == 401:
                            raise MissingKey("BuiltWith")
        except Exception as e:
            print(f"Error in BuiltWith search: {e}")

    def _extract_data(self) -> None:
        """Extract and categorize technology information."""
        if 'domains' in self.tech_stack:
            self.hosts.update(self.tech_stack['domains'])
        if 'paths' in self.tech_stack:
            self.interesting_urls.update(self.tech_stack['paths'])
        if 'technologies' in self.tech_stack:
            for tech in self.tech_stack['technologies']:
                category = tech.get('category', '').lower()
                name = tech.get('name', '')
                
                if 'framework' in category:
                    self.frameworks.add(name)
                elif 'language' in category:
                    self.languages.add(name)
                elif 'server' in category:
                    self.servers.add(name)
                elif 'cms' in category:
                    self.cms.add(name)
                elif 'analytics' in category:
                    self.analytics.add(name)

    async def get_hostnames(self) -> Set[str]:
        return self.hosts

    async def get_tech_stack(self) -> Dict:
        return self.tech_stack

    async def get_interesting_urls(self) -> Set[str]:
        return self.interesting_urls

    async def get_frameworks(self) -> Set[str]:
        return self.frameworks

    async def get_languages(self) -> Set[str]:
        return self.languages

    async def get_servers(self) -> Set[str]:
        return self.servers

    async def get_cms(self) -> Set[str]:
        return self.cms

    async def get_analytics(self) -> Set[str]:
        return self.analytics 