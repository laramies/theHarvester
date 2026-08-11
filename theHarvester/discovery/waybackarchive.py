import asyncio
import logging
from urllib.parse import unquote_plus, urlencode, urlsplit

from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)


class SearchWaybackarchive:
    """Use the Internet Archive Wayback CDX API to find historical subdomains.

    API documentation: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
    """

    PAGE_SIZE = 1000
    RUNTIME_SECONDS = 30.0
    # ponytail: hard cap protects against endless cursors; raise only if real targets exceed one million rows.
    MAX_PAGES_PER_QUERY = 1000

    def __init__(self, word, limit: int = 500) -> None:
        self.word = word.strip().rstrip('.').lower()
        self.limit = max(limit, 0)
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://web.archive.org'
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

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
    def _parse_page(payload: object) -> tuple[list[str], str | None] | None:
        if not isinstance(payload, str) or payload.lstrip().startswith('<'):
            return None

        body, separator, continuation = payload.replace('\r\n', '\n').rpartition('\n\n')
        if not separator:
            return payload.splitlines(), None

        continuation_lines = [line.strip() for line in continuation.splitlines() if line.strip()]
        return body.splitlines(), continuation_lines[0] if len(continuation_lines) == 1 else None

    async def _search_pattern(self, pattern: str, headers: dict[str, str]) -> str | None:
        resume_key: str | None = None
        seen_resume_keys: set[str] = set()
        for page_number in range(1, self.MAX_PAGES_PER_QUERY + 1):
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
            if not response or not isinstance(response, list):
                logger.info(f'Wayback Archive returned an invalid response container for pattern {pattern}')
                return 'invalid-response'
            if not response[0]:
                logger.info(f'Wayback Archive returned no page data for pattern {pattern}')
                return None

            page = self._parse_page(response[0])
            if page is None:
                logger.info(f'Wayback Archive returned invalid page data for pattern {pattern}; stopping pagination')
                return 'invalid-response'
            lines, next_resume_key = page
            for line in lines:
                if not line:
                    continue
                domain = self._extract_domain_from_url(line.strip())
                if domain.endswith(f'.{self.word}') or domain == self.word:
                    self.totalhosts.add(domain)
                    if len(self.totalhosts) >= self.limit:
                        return 'result-limit'

            if page_number == 1 or page_number % 10 == 0:
                logger.info(f'Wayback Archive page {page_number}: hosts={len(self.totalhosts)}')

            if next_resume_key is None or next_resume_key in seen_resume_keys:
                return None
            seen_resume_keys.add(next_resume_key)
            resume_key = next_resume_key
        logger.info(f'Wayback Archive page limit reached for pattern {pattern}; results may be incomplete')
        return 'page-limit'

    async def do_search(self) -> None:
        self.execution_status = None
        self.stop_reason = None
        if self.limit == 0:
            return
        try:
            headers = {'User-agent': Core.get_user_agent()}
            degraded_reason: str | None = None
            try:
                async with asyncio.timeout(self.RUNTIME_SECONDS):
                    for pattern in (f'*.{self.word}', f'{self.word}/*'):
                        try:
                            outcome = await self._search_pattern(pattern, headers)
                        except Exception as e:
                            degraded_reason = degraded_reason or 'request-error'
                            logger.info(f'Wayback Archive API error for pattern {pattern}: {e}')
                            continue
                        if outcome == 'result-limit':
                            if degraded_reason is None:
                                self.stop_reason = 'result-limit'
                            break
                        if outcome == 'page-limit':
                            degraded_reason = degraded_reason or outcome
                            break
                        if outcome is not None:
                            degraded_reason = degraded_reason or outcome
            except TimeoutError:
                self.execution_status = 'partial' if self.totalhosts else 'failed'
                self.stop_reason = 'runtime-limit'
                logger.info(
                    f'Wayback Archive runtime limit reached after {self.RUNTIME_SECONDS:g}s; '
                    f'preserved {len(self.totalhosts)} hosts'
                )
                return
            if degraded_reason is not None:
                self.execution_status = 'partial' if self.totalhosts or degraded_reason == 'page-limit' else 'failed'
                self.stop_reason = degraded_reason
        except Exception as e:
            self.execution_status = 'partial' if self.totalhosts else 'failed'
            self.stop_reason = 'unexpected-error'
            logger.info(f'Wayback Archive API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
