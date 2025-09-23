import re

from theHarvester.lib.core import AsyncFetcher, Core


class SearchWaybackarchive:
    """
    Class uses Internet Archive's Wayback Machine CDX API to find historical subdomains
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://web.archive.org'

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

            # Search for subdomains in wayback machine
            # Using different approaches due to API timeout issues

            # Method 1: Search for wildcard subdomains (limited results to avoid timeout)
            urls_to_try = [
                f'{self.hostname}/cdx/search/cdx?url=*.{self.word}&fl=original&collapse=urlkey&limit=100',
                f'{self.hostname}/cdx/search/cdx?url={self.word}/*&fl=original&collapse=urlkey&limit=50',
            ]

            for url in urls_to_try:
                try:
                    response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

                    if not response or not isinstance(response, list) or not response[0]:
                        continue

                    # Parse line-by-line response (not JSON)
                    lines = response[0].strip().split('\n') if isinstance(response[0], str) else []

                    for line in lines:
                        if line and not line.startswith('<'):  # Skip HTML error messages
                            # Each line is a URL
                            domain = self._extract_domain_from_url(line.strip())

                            # Check if it's a subdomain of our target
                            if domain.endswith(f'.{self.word}') or domain == self.word:
                                self.totalhosts.add(domain)

                except Exception as e:
                    print(f'Wayback Archive API error for URL {url}: {e}')
                    continue

        except Exception as e:
            print(f'Wayback Archive API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
