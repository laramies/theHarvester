import asyncio
from email.errors import HeaderParseError
from email.headerregistry import Address
from urllib.parse import urlparse

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import intelxparser


class SearchIntelx:
    """Search the Intelligence X Phonebook API."""

    PAGE_SIZE = 1000
    UNLIMITED_QUERY_RESULTS = 2**31 - 1
    MAX_PENDING_POLLS = 30
    MAX_RUNTIME_SECONDS = 60.0

    def __init__(self, word: str, limit: int | None = None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('IntelX limit must be a positive integer or None')
        self.word = word
        self.key = Core.intelx_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('Intelx')
        self.database = 'https://2.intelx.io'
        self.results: dict[str, list[object]] = {'selectors': []}
        self.emails: list[str] = []
        self.hostnames: list[str] = []
        self.urls: list[str] = []
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'x-key': self.key, 'User-Agent': Core.get_user_agent(), 'Content-Type': 'application/json'}
        search_limit = self.limit if self.limit is not None else self.UNLIMITED_QUERY_RESULTS
        data = {
            'term': self.word,
            'buckets': [],
            'lookuplevel': 0,
            'maxresults': search_limit,
            'timeout': 5,
            'datefrom': '',
            'dateto': '',
            'sort': 4,
            'media': 0,
            'terminate': [],
            'target': 0,
        }
        collected = 0
        pending_polls = 0
        try:
            async with asyncio.timeout(self.MAX_RUNTIME_SECONDS):
                async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy) as session:
                    async with session.post(f'{self.database}/phonebook/search', headers=headers, json=data) as response:
                        if response.status in {401, 403}:
                            return SourceExecutionReport('failed', 'access-denied')
                        if response.status == 429:
                            return SourceExecutionReport('rate-limited', 'http-429')
                        if not 200 <= response.status < 300:
                            return SourceExecutionReport('failed', f'http-{response.status}')
                        search_data = await response.json()
                    if (
                        not isinstance(search_data, dict)
                        or search_data.get('success') is False
                        or not isinstance(search_data.get('id'), str)
                        or not search_data['id']
                    ):
                        return SourceExecutionReport('failed', 'invalid-response')
                    phonebook_id = search_data['id']
                    while self.limit is None or collected < self.limit:
                        page_size = min(self.PAGE_SIZE, self.limit - collected) if self.limit is not None else self.PAGE_SIZE
                        async with session.get(
                            f'{self.database}/phonebook/search/result',
                            headers=headers,
                            params={'id': phonebook_id, 'limit': page_size},
                        ) as response:
                            if response.status in {401, 403}:
                                return SourceExecutionReport('failed', 'access-denied')
                            if response.status == 429:
                                return SourceExecutionReport('rate-limited', 'http-429')
                            if not 200 <= response.status < 300:
                                return SourceExecutionReport('failed', f'http-{response.status}')
                            page = await response.json()
                        if (
                            not isinstance(page, dict)
                            or isinstance(page.get('status'), bool)
                            or not isinstance(page.get('status'), int)
                        ):
                            return SourceExecutionReport('failed', 'invalid-response')
                        status = page['status']
                        if status == 2:
                            return SourceExecutionReport('failed', 'search-not-found')
                        if status == 4:
                            return SourceExecutionReport('failed', 'provider-error')
                        if status not in {0, 1, 3}:
                            return SourceExecutionReport('failed', 'invalid-response')
                        selectors = page.get('selectors', [])
                        if not isinstance(selectors, list):
                            return SourceExecutionReport('failed', 'invalid-response')
                        if status == 3:
                            pending_polls += 1
                            if pending_polls >= self.MAX_PENDING_POLLS:
                                return SourceExecutionReport('partial', 'runtime-limit')
                            await asyncio.sleep(1)
                            continue
                        if status == 0 and not selectors:
                            return SourceExecutionReport('failed', 'invalid-response')
                        pending_polls = 0
                        retained = selectors[:page_size]
                        self.results['selectors'].extend(retained)
                        collected += len(retained)
                        if status == 1 or (self.limit is not None and collected >= self.limit):
                            return None
        except TimeoutError:
            return SourceExecutionReport('partial', 'runtime-limit')
        except asyncio.CancelledError:
            raise
        except aiohttp.ClientError, OSError:
            return SourceExecutionReport('failed', 'transport-error')
        return None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        report = await self.do_search()
        intelx_parser = intelxparser.Parser()
        raw_emails, raw_selectors = await intelx_parser.parse_dictionaries(self.results)
        emails: set[str] = set()
        urls: set[str] = set()
        hostnames: set[str] = set()
        for email in raw_emails:
            if email.count('@') != 1:
                continue
            try:
                address = Address(addr_spec=email.strip().lower())
            except HeaderParseError, ValueError:
                continue
            if address.username and (normalized_domain := normalize_scoped_hostname(address.domain, self.word)):
                emails.add(f'{address.username}@{normalized_domain}')
        for selector in raw_selectors:
            selector = selector.strip()
            try:
                parsed = urlparse(selector if '://' in selector else f'//{selector}')
            except ValueError:
                continue
            normalized_hostname = normalize_scoped_hostname(parsed.hostname, self.word)
            if normalized_hostname:
                hostnames.add(normalized_hostname)
                if parsed.scheme in {'http', 'https'} and parsed.netloc:
                    urls.add(selector)
        self.emails = sorted(emails)
        self.urls = sorted(urls)
        self.hostnames = sorted(hostnames)
        return report

    async def get_emails(self) -> list[str]:
        return self.emails

    async def get_hostnames(self) -> list[str]:
        return self.hostnames

    async def get_urls(self) -> list[str]:
        return self.urls
