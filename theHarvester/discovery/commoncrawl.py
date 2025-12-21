import json as _stdlib_json
import re
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchCommoncrawl:
    """
    Class uses Common Crawl index API to gather subdomains from archived web data
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://index.commoncrawl.org'

    @staticmethod
    def _safe_parse_json_lines(payload: str) -> list:
        """Parse JSON lines format"""
        results: list = []
        if not payload:
            return results

        for line in payload.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except Exception:
                    continue
        return results

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        if not url:
            return ''

        # Remove protocol
        url = re.sub(r'^https?://', '', url)

        # Extract domain part (before first /)
        domain = url.split('/')[0]

        # Remove port if present
        domain = domain.split(':')[0]

        return domain.lower()

    async def do_search(self) -> None:
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Use recent Common Crawl indexes
            indexes = [
                'CC-MAIN-2024-18',  # April 2024
                'CC-MAIN-2024-10',  # February 2024
                'CC-MAIN-2023-50',  # December 2023
            ]

            for index in indexes:
                try:
                    # Search for subdomains using wildcard
                    url = f'{self.hostname}/{index}-index?url=*.{self.word}&output=json&limit=1000'

                    response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

                    if not response or not isinstance(response, list) or not response[0]:
                        continue

                    try:
                        data = self._safe_parse_json_lines(response[0])
                    except Exception as e:
                        print(f'Failed to parse Common Crawl response for {index}: {e}')
                        continue

                    # Extract domains from URLs
                    for record in data:
                        if isinstance(record, dict):
                            original_url = record.get('url', '')
                            if original_url:
                                domain = self._extract_domain_from_url(original_url)

                                # Check if it's a subdomain of our target
                                if domain.endswith(f'.{self.word}') or domain == self.word:
                                    self.totalhosts.add(domain)

                    # Also search for the main domain
                    main_url = f'{self.hostname}/{index}-index?url={self.word}/*&output=json&limit=100'

                    main_response = await AsyncFetcher.fetch_all([main_url], headers=headers, proxy=self.proxy)

                    if main_response and isinstance(main_response, list) and main_response[0]:
                        try:
                            main_data = self._safe_parse_json_lines(main_response[0])
                            for record in main_data:
                                if isinstance(record, dict):
                                    original_url = record.get('url', '')
                                    if original_url:
                                        domain = self._extract_domain_from_url(original_url)
                                        if domain.endswith(f'.{self.word}') or domain == self.word:
                                            self.totalhosts.add(domain)
                        except Exception as e:
                            print(f'Failed to parse Common Crawl main domain response for {index}: {e}')

                except Exception as e:
                    print(f'Common Crawl API error for index {index}: {e}')
                    continue

        except Exception as e:
            print(f'Common Crawl API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
