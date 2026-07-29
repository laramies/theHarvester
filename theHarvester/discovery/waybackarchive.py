import logging
from urllib.parse import unquote_plus, urlencode, urlsplit

from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)


class SearchWaybackarchive:
    """Use the Internet Archive Wayback CDX API to find historical subdomains.

    API documentation: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
    """

    PAGE_SIZE = 1000
    # ponytail: hard cap protects against endless cursors; raise only if real targets exceed one million rows.
    MAX_PAGES_PER_QUERY = 1000

    def __init__(self, word) -> None:
        self.word = word.strip().rstrip('.').lower()
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://web.archive.org'

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        if not url:
            return ''
        try:
            parsed = urlsplit(url if '://' in url else f'//{url}')
            hostname = (parsed.hostname or '').rstrip('.').lower()
        except ValueError:
            return ''
        if len(hostname) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith('-')
            or label.endswith('-')
            or not all(character.isascii() and (character.isalnum() or character == '-') for character in label)
            for label in hostname.split('.')
        ):
            return ''
        return hostname

    @staticmethod
    def _parse_page(payload: str) -> tuple[list[str], str | None]:
        if not isinstance(payload, str) or payload.lstrip().startswith('<'):
            return [], None

        body, separator, continuation = payload.replace('\r\n', '\n').rpartition('\n\n')
        if not separator:
            return payload.splitlines(), None

        continuation_lines = [line.strip() for line in continuation.splitlines() if line.strip()]
        return body.splitlines(), continuation_lines[0] if len(continuation_lines) == 1 else None

    async def _search_pattern(self, pattern: str, headers: dict[str, str]) -> None:
        resume_key: str | None = None
        seen_resume_keys: set[str] = set()
        for _ in range(self.MAX_PAGES_PER_QUERY):
            query = {
                'url': pattern,
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': self.PAGE_SIZE,
                'showResumeKey': 'true',
            }
            if resume_key is not None:
                query['resumeKey'] = unquote_plus(resume_key)

            url = f'{self.hostname}/cdx/search/cdx?{urlencode(query)}'
            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
            if not response or not isinstance(response, list) or not response[0]:
                return

            lines, next_resume_key = self._parse_page(response[0])
            for line in lines:
                if not line:
                    continue
                domain = self._extract_domain_from_url(line.strip())
                if domain.endswith(f'.{self.word}') or domain == self.word:
                    self.totalhosts.add(domain)

            if next_resume_key is None or next_resume_key in seen_resume_keys:
                return
            seen_resume_keys.add(next_resume_key)
            resume_key = next_resume_key

    async def do_search(self) -> None:
        try:
            headers = {'User-agent': Core.get_user_agent()}

            for pattern in (f'*.{self.word}', f'{self.word}/*'):
                try:
                    await self._search_pattern(pattern, headers)

                except Exception as e:
                    logger.info(f'Wayback Archive API error for pattern {pattern}: {e}')
                    continue

        except Exception as e:
            logger.info(f'Wayback Archive API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
