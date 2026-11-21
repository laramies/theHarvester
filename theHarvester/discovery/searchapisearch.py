import asyncio
import ssl
from typing import Any
from urllib.parse import urlencode, urlparse

import aiohttp

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.configuration import CredentialAdapter, FileSystemCredentialAdapter
from theHarvester.lib.core import AsyncFetcher, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchSearchApi:
    """Search Google results through SearchApi while allowing credentials to be injected.

    Provider API:
    https://www.searchapi.io/docs/google

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    # Google serves at most ten organic rows per page through this engine; a
    # larger num is clamped to ten and every request is billed the same, so the
    # adapter asks for whole pages and trims rows locally.
    PAGE_SIZE = 10

    # Ten pages is a provider boundary guard, not a theHarvester result cap: it
    # bounds the conversation when a query keeps reporting a next page, and
    # reaching it is reported as partial coverage.
    MAX_PAGES = 10

    def __init__(self, word: str, limit: int | None, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        try:
            self.api_key = credentials.get('searchapi')
        except KeyError:
            raise MissingKey('SearchApi') from None
        if self.api_key is None or self.api_key == '':
            raise MissingKey('SearchApi')
        self.server = 'https://www.searchapi.io/api/v1/search'
        self.limit = limit
        self.proxy: bool | str = False

    @staticmethod
    def _is_google_redirect(link: str) -> bool:
        """Google serves some lower-ranked rows as google.com/goto redirects.

        Their url parameter is an opaque token rather than the destination, so the
        row's own domain and displayed link are the only host evidence they carry.
        """
        parsed = urlparse(link)
        host = (parsed.hostname or '').lower()
        return (host == 'google.com' or host.endswith('.google.com')) and parsed.path == '/goto'

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

        # Both queries often return the same pages, and Google windows overlap
        # within one query. Each link counts once against the limit, but every
        # row's text is kept for parsing, because a repeated link can carry a
        # different snippet with new evidence.
        texts_by_link: dict[str, set[str]] = {}
        # A query stopped by the page bound leaves coverage incomplete even when
        # the other query exhausts normally, so the outcome is kept until the end.
        truncated = False
        limit_reached = False
        for query in queries:
            if self.limit is not None and len(self.results) >= self.limit:
                break
            # Pages are numbered from one; the response names the next page only
            # while Google has one, and that field alone decides whether the
            # query goes on: a window that only repeats earlier rows is not
            # evidence of exhaustion.
            try:
                for page in range(1, self.MAX_PAGES + 1):
                    if self.limit is not None and len(self.results) >= self.limit:
                        break
                    params = {'engine': 'google', 'q': query, 'page': page}
                    url = f'{self.server}?{urlencode(params)}'

                    response = await AsyncFetcher.fetch_json(
                        url,
                        session=session,
                        headers=headers,
                    )
                    if failure := provider_http_error(response):
                        return SourceExecutionReport(*failure)
                    resp = response.body

                    # Every successful answer carries the search_metadata envelope;
                    # refusals arrive as non-2xx statuses and are classified above.
                    if not isinstance(resp, dict) or not isinstance(resp.get('search_metadata'), dict):
                        return SourceExecutionReport('failed', 'invalid-response')

                    # A query or page without results keeps the envelope but drops
                    # organic_results (SearchApi says so in an error string for a
                    # query with no results at all). That is a normal end of the
                    # query, not a failure.
                    rows = resp.get('organic_results')
                    if rows is None:
                        break
                    if not isinstance(rows, list):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if any(not isinstance(row, dict) for row in rows):
                        return SourceExecutionReport('failed', 'invalid-response')

                    if not rows:
                        break

                    for row in rows:
                        title = row.get('title') or ''
                        snippet = row.get('snippet') or ''
                        link = row.get('link') or ''
                        domain = row.get('domain') or ''
                        displayed_link = row.get('displayed_link') or ''
                        if not all(isinstance(value, str) for value in (title, snippet, link, domain, displayed_link)):
                            return SourceExecutionReport('failed', 'invalid-response')
                        if not link and not domain:
                            continue
                        if self._is_google_redirect(link):
                            # The redirect token changes between requests, so the
                            # displayed link (or the domain) identifies the row, and
                            # the google.com address never becomes evidence.
                            key = displayed_link or f'{domain} {title}'
                            evidence_link = f'{displayed_link} {domain}'.strip()
                        else:
                            key = link or f'{domain} {title}'
                            evidence_link = f'{link} {domain}'.strip()
                        text = f'{title} {snippet} {evidence_link}\n'
                        known = texts_by_link.get(key)
                        if known is not None:
                            # Already counted, by this query or the other one:
                            # keep only text not seen for this link.
                            if text not in known:
                                known.add(text)
                                self.totalresults += text
                            continue
                        # Rows are trimmed here because a page always holds up
                        # to ten rows regardless of the remaining allowance.
                        if self.limit is not None and len(self.results) >= self.limit:
                            continue
                        texts_by_link[key] = {text}
                        self.totalresults += text
                        self.results.append(
                            {
                                'title': title,
                                'snippet': snippet,
                                'link': link,
                                'domain': domain,
                                'displayed_link': displayed_link,
                            }
                        )
                    if self.limit is not None and len(self.results) >= self.limit:
                        # The allowance is full, but whether the run is complete
                        # still depends on whether an earlier query hit the page
                        # bound, so the outcome is decided after the query loop.
                        limit_reached = True
                        break

                    pagination = resp.get('pagination')
                    if not isinstance(pagination, dict) or not pagination.get('next'):
                        break

                    await asyncio.sleep(get_delay())
                else:
                    # The provider still advertised a page past the bound; the
                    # other query runs, but coverage of this one is incomplete.
                    truncated = True

            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)
        # A query stopped at the page bound leaves coverage incomplete even when
        # a later query then filled the allowance; saved-run comparisons rely on
        # that distinction to avoid marking missing findings as no longer reported.
        if truncated:
            return SourceExecutionReport('partial', 'provider-limit')
        if limit_reached:
            return SourceExecutionReport('completed', 'result-limit')
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
