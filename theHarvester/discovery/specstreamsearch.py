import asyncio
import ssl
from typing import Any
from urllib.parse import urlencode

import aiohttp

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.configuration import CredentialAdapter, FileSystemCredentialAdapter
from theHarvester.lib.core import AsyncFetcher, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchSpecstream:
    """Search the web through the SpecStream Search API while allowing credentials to be injected.

    Provider API:
    https://specstream.ai/agents.md

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    # A page holds num results (at most ten here) and later pages continue the
    # same list only when num stays the same, so num is fixed for each query and
    # rows are trimmed here. next_page is null once the engines have no more.
    PAGE_SIZE = 10

    # The API serves pages 1 to 10 of a query; a next_page past that means the
    # provider maximum hid further results.
    MAX_PAGES = 10

    def __init__(self, word: str, limit: int | None, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        try:
            self.api_key = credentials.get('specstream')
        except KeyError:
            raise MissingKey('SpecStream') from None
        if self.api_key is None or self.api_key == '':
            raise MissingKey('SpecStream')
        self.server = 'https://api.specstream.ai/v1/web-search'
        self.limit = limit
        self.proxy: bool | str = False

    async def do_search(self, session: Any | None = None) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.api_key}'}
        if session is None:
            try:
                async with AsyncFetcher.open_session(
                    headers=headers,
                    proxy=self.proxy,
                    request_timeout=60,
                ) as owned_session:
                    return await self.do_search(owned_session)
            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)

        # Search queries: exact match and site-specific
        queries = [f'"{self.word}"', f'site:{self.word}']

        # Both queries often return the same pages. Each link counts once
        # against the limit, but every row's text is kept for parsing, because
        # the same URL can carry a different snippet with new evidence.
        texts_by_link: dict[str, set[str]] = {}
        capped = False
        first_request = True
        for query in queries:
            if self.limit is not None and len(self.results) >= self.limit:
                break
            remaining = self.limit - len(self.results) if self.limit is not None else self.PAGE_SIZE
            num = min(self.PAGE_SIZE, remaining)
            page: int | None = 1
            while page is not None:
                if page > self.MAX_PAGES:
                    capped = True
                    break
                if not first_request:
                    await asyncio.sleep(get_delay())
                first_request = False
                # speed=fast returns the engines' ranked results with their
                # snippets, without the answer the default search reads pages for.
                params = {'q': query, 'num': num, 'page': page, 'speed': 'fast'}
                url = f'{self.server}?{urlencode(params)}'
                try:
                    response = await AsyncFetcher.fetch_json(
                        url,
                        session=session,
                        headers=headers,
                    )
                except ResponseStreamError as error:
                    return SourceExecutionReport('failed', error.reason)
                if failure := provider_http_error(response):
                    return SourceExecutionReport(*failure)
                resp = response.body

                # Every reply is one object; results are under data.
                data = resp.get('data') if isinstance(resp, dict) else None
                if not isinstance(data, dict):
                    return SourceExecutionReport('failed', 'invalid-response')
                sources = data.get('sources')
                if not isinstance(sources, list):
                    return SourceExecutionReport('failed', 'invalid-response')
                if any(not isinstance(source, dict) for source in sources):
                    return SourceExecutionReport('failed', 'invalid-response')
                next_page = data.get('next_page')
                if next_page is not None and (not isinstance(next_page, int) or isinstance(next_page, bool) or next_page <= page):
                    return SourceExecutionReport('failed', 'invalid-response')

                rows = []
                for source in sources:
                    title = source.get('title') or ''
                    snippet = source.get('snippet') or ''
                    link = source.get('url') or ''
                    if not all(isinstance(value, str) for value in (title, snippet, link)):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if link:
                        rows.append({'title': title, 'snippet': snippet, 'url': link})

                for row in rows:
                    text = f'{row["title"]} {row["snippet"]} {row["url"]}\n'
                    known = texts_by_link.get(row['url'])
                    if known is not None:
                        # Counted already; keep only text not seen for this link.
                        if text not in known:
                            known.add(text)
                            self.totalresults += text
                        continue
                    if self.limit is not None and len(self.results) >= self.limit:
                        continue
                    texts_by_link[row['url']] = {text}
                    self.totalresults += text
                    self.results.append(row)
                if self.limit is not None and len(self.results) >= self.limit:
                    return SourceExecutionReport('completed', 'result-limit')
                page = next_page
        if capped:
            return SourceExecutionReport('partial', 'provider-limit')
        return None

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except asyncio.CancelledError:
            raise
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError:
            return SourceExecutionReport('failed', 'transport-error')
