from typing import Any

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchBuiltWith:
    def __init__(self, word: str):
        self.word = word
        self.api_key = Core.builtwith_key()
        if self.api_key is None:
            raise MissingKey('BuiltWith')
        self.base_url = 'https://api.builtwith.com/v21/api.json'
        self.headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        self.hosts: set[str] = set()
        self.tech_stack: dict[str, Any] = {}
        self.interesting_urls: set[str] = set()
        self.frameworks: set[str] = set()
        self.languages: set[str] = set()
        self.servers: set[str] = set()
        self.cms: set[str] = set()
        self.analytics: set[str] = set()

    async def process(self, proxy: bool = False) -> None:
        """Get technology stack information for a domain."""
        try:
            if proxy:
                response = await AsyncFetcher.fetch(
                    session=None, url=f'{self.base_url}?KEY={self.api_key}&LOOKUP={self.word}', headers=self.headers, proxy=proxy
                )
                if response:
                    self.tech_stack = response
                    self._extract_data()
            else:
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(f'{self.base_url}?KEY={self.api_key}&LOOKUP={self.word}') as response:
                        if response.status == 200:
                            data = await response.json()
                            self.tech_stack = data
                            self._extract_data()
        except Exception as e:
            print(f'Error in BuiltWith search: {e}')

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

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_tech_stack(self) -> dict:
        return self.tech_stack

    async def get_interesting_urls(self) -> set[str]:
        return self.interesting_urls

    async def get_frameworks(self) -> set[str]:
        return self.frameworks

    async def get_languages(self) -> set[str]:
        return self.languages

    async def get_servers(self) -> set[str]:
        return self.servers

    async def get_cms(self) -> set[str]:
        return self.cms

    async def get_analytics(self) -> set[str]:
        return self.analytics
