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


class SearchSerply:
    """Search Google results through Serply while allowing credentials to be injected.

    Provider API:
    https://serply.io/docs

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    # Serply returns at most ten organic rows per response and paginates with a
    # start offset. The num parameter is an approximate cap rather than an exact
    # count, so rows are trimmed here.
    PAGE_SIZE = 10

    # Ten pages is a provider boundary guard, not a theHarvester result cap: it
    # bounds the conversation when a query keeps reporting further pages.
    MAX_PAGES = 10

    def __init__(self, word: str, limit: int | None, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        try:
            self.api_key = credentials.get('serply')
        except KeyError:
            raise MissingKey('Serply') from None
        if self.api_key is None or self.api_key == '':
            raise MissingKey('Serply')
        self.server = 'https://api.serply.io/v1/search/'
        self.limit = limit
        self.proxy: bool | str = False

    async def do_search(self, session: Any | None = None) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'X-Api-Key': self.api_key}
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

        for query in queries:
            if self.limit is not None and len(self.results) >= self.limit:
                break
            # Serply ignores page and offset; start is the only parameter that
            # advances the result window.
            seen_links: set[str] = set()
            try:
                for page in range(self.MAX_PAGES):
                    remaining = self.limit - len(self.results) if self.limit is not None else self.PAGE_SIZE
                    if self.limit is not None and remaining <= 0:
                        break
                    params = {
                        'q': query,
                        'num': min(self.PAGE_SIZE, remaining),
                        'start': page * self.PAGE_SIZE,
                    }
                    url = f'{self.server}?{urlencode(params)}'

                    response = await AsyncFetcher.fetch_json(
                        url,
                        session=session,
                        headers=headers,
                    )
                    if failure := provider_http_error(response):
                        return SourceExecutionReport(*failure)
                    resp = response.body

                    if not isinstance(resp, dict):
                        return SourceExecutionReport('failed', 'invalid-response')

                    # Serply reports refusals as a detail string rather than an
                    # organic payload.
                    if 'results' not in resp:
                        if 'detail' in resp:
                            return SourceExecutionReport('failed', 'provider-error')
                        return SourceExecutionReport('failed', 'invalid-response')

                    rows = resp['results']
                    if not isinstance(rows, list):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if any(not isinstance(row, dict) for row in rows):
                        return SourceExecutionReport('failed', 'invalid-response')

                    if not rows:
                        break

                    # Deduplicate the whole page before trimming to the limit:
                    # Google windows can overlap, and a page whose first rows
                    # repeat the previous window may still carry fresh links
                    # further down.
                    fresh = []
                    for result in rows:
                        title = result.get('title', '')
                        description = result.get('description', '')
                        link = result.get('link', '')
                        if not all(isinstance(value, str) for value in (title, description, link)):
                            return SourceExecutionReport('failed', 'invalid-response')
                        if link in seen_links:
                            continue
                        seen_links.add(link)
                        fresh.append(result)

                    # A page that only repeats the previous window means the
                    # provider has no further results for this query.
                    if not fresh:
                        break

                    for result in fresh[:remaining]:
                        self.totalresults += f'{result["title"]} {result["description"]} {result["link"]}\n'
                        self.results.append(result)
                    if self.limit is not None and len(self.results) >= self.limit:
                        return SourceExecutionReport('completed', 'result-limit')
                    if len(rows) < params['num']:
                        break

                    await asyncio.sleep(get_delay())
                else:
                    return SourceExecutionReport('partial', 'provider-limit')

            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)
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
