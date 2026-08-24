import asyncio
import ssl
from typing import Any
from urllib.parse import quote

import aiohttp

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.configuration import CredentialAdapter, FileSystemCredentialAdapter
from theHarvester.lib.core import AsyncFetcher, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchBrave:
    """Search Brave while allowing credentials to be supplied without file access.

    Provider API:
    https://api-dashboard.search.brave.com/app/documentation/web-search/query

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    # Brave documents offsets 0 through 9; this is a provider boundary, not a
    # theHarvester result cap.
    MAX_OFFSET = 9

    def __init__(self, word: str, limit: int | None, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        try:
            self.api_key = credentials.get('brave')
        except KeyError:
            raise MissingKey('Brave Search') from None
        if self.api_key is None or self.api_key == '':
            raise MissingKey('Brave Search')
        self.server = 'https://api.search.brave.com/res/v1/web/search'
        self.limit = limit
        self.proxy: bool | str = False

    async def do_search(self, session: Any | None = None) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'gzip', 'X-Subscription-Token': self.api_key}
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
            try:
                for offset in range(self.MAX_OFFSET + 1):
                    remaining = self.limit - len(self.results) if self.limit is not None else 20
                    if self.limit is not None and remaining <= 0:
                        break
                    params = {
                        'q': query,
                        'count': min(20, remaining),
                        'offset': offset,
                        'safesearch': 'off',
                        'freshness': 'all',
                        'extra_snippets': 'true',  # Enable extra snippets for richer content
                        'text_decorations': 'true',  # Enable highlighting
                        'spellcheck': 'true',  # Enable spellcheck
                    }

                    # Build URL with parameters
                    param_string = '&'.join([f'{k}={quote(str(v))}' for k, v in params.items()])
                    url = f'{self.server}?{param_string}'

                    response = await AsyncFetcher.fetch_json(
                        url,
                        session=session,
                        headers=headers,
                    )
                    if failure := provider_http_error(response):
                        return SourceExecutionReport(*failure)
                    resp = response.body

                    # Handle API response
                    if resp is None:
                        return SourceExecutionReport('failed', 'invalid-response')
                    if not isinstance(resp, dict):
                        return SourceExecutionReport('failed', 'invalid-response')

                    # Check for API errors (rate limit, quota exceeded, etc.)
                    if 'error' in resp:
                        provider_error = resp['error']
                        if not isinstance(provider_error, dict):
                            return SourceExecutionReport('failed', 'invalid-response')
                        error_message = str(provider_error.get('message', '')).lower()
                        error_code = str(provider_error.get('code', '')).lower()
                        if 'rate limit' in error_message or error_code == 'rate_limit_exceeded':
                            return SourceExecutionReport('rate-limited', 'provider-rate-limit')
                        if 'quota' in error_message or error_code == 'quota_exceeded':
                            return SourceExecutionReport('failed', 'quota-exhausted')
                        return SourceExecutionReport('failed', 'provider-error')

                    web = resp.get('web')
                    query_data = resp.get('query')
                    if not isinstance(web, dict) or not isinstance(web.get('results'), list):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if not isinstance(query_data, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    more_results_available = query_data.get('more_results_available')
                    if not isinstance(more_results_available, bool):
                        return SourceExecutionReport('failed', 'invalid-response')

                    results = web['results'][:remaining]
                    if any(not isinstance(result, dict) for result in results):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if not results:
                        if more_results_available:
                            return SourceExecutionReport('failed', 'invalid-response')
                        break

                    for result in results:
                        snippets = result.get('extra_snippets', [])
                        if not isinstance(snippets, list) or any(not isinstance(snippet, str) for snippet in snippets):
                            return SourceExecutionReport('failed', 'invalid-response')
                        title = result.get('title', '')
                        description = result.get('description', '')
                        result_url = result.get('url', '')
                        if not all(isinstance(value, str) for value in (title, description, result_url)):
                            return SourceExecutionReport('failed', 'invalid-response')
                        result_text = f'{title} {description}'
                        for snippet in snippets:
                            result_text += f' {snippet}'
                        result_text += f' {result_url}'
                        self.totalresults += result_text + '\n'

                    self.results.extend(results)
                    if self.limit is not None and len(self.results) >= self.limit:
                        return SourceExecutionReport('completed', 'result-limit')
                    if not more_results_available:
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
