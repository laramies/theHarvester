import asyncio
import ssl
from typing import Any

import aiohttp

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.configuration import CredentialAdapter, FileSystemCredentialAdapter
from theHarvester.lib.core import MAX_PROVIDER_JSON_BYTES, AsyncFetcher, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchOutcrawl:
    """Search the web through Outcrawl while allowing credentials to be injected.

    Provider API:
    https://outcrawl.ai/docs/search/overview

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    PAGE_SIZE = 20

    def __init__(self, word: str, limit: int | None, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        try:
            self.api_key = credentials.get('outcrawl')
        except KeyError:
            raise MissingKey('Outcrawl') from None
        if self.api_key is None or self.api_key == '':
            raise MissingKey('Outcrawl')
        self.server = 'https://api.outcrawl.ai/v1/search'
        self.limit = limit
        self.proxy: bool | str = False

    async def do_search(self, session: Any | None = None) -> SourceExecutionReport | None:
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
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

        queries = [f'"{self.word}"', f'site:{self.word}']

        texts_by_link: dict[str, set[str]] = {}
        capped = False
        for index, query in enumerate(queries):
            remaining = self.limit - len(self.results) if self.limit is not None else self.PAGE_SIZE
            if self.limit is not None and remaining <= 0:
                break
            if index:
                await asyncio.sleep(get_delay())
            requested = min(self.PAGE_SIZE, remaining + len(texts_by_link))
            payload = {'query': query, 'limit': requested}
            try:
                response = await AsyncFetcher.post_fetch(
                    self.server,
                    session=session,
                    headers=headers,
                    json=True,
                    json_body=payload,
                    include_metadata=True,
                    response_byte_limit=MAX_PROVIDER_JSON_BYTES,
                )
            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)
            if failure := provider_http_error(response):
                return SourceExecutionReport(*failure)
            resp = response.body

            if not isinstance(resp, dict):
                return SourceExecutionReport('failed', 'invalid-response')

            hits = resp.get('hits')
            if not isinstance(hits, list):
                return SourceExecutionReport('failed', 'invalid-response')
            if any(not isinstance(hit, dict) for hit in hits):
                return SourceExecutionReport('failed', 'invalid-response')

            rows = []
            for hit in hits:
                title = hit.get('title') or ''
                snippet = hit.get('snippet') or ''
                url = hit.get('url') or ''
                if not all(isinstance(value, str) for value in (title, snippet, url)):
                    return SourceExecutionReport('failed', 'invalid-response')
                if url:
                    rows.append({'title': title, 'snippet': snippet, 'url': url})

            for row in rows:
                text = f'{row["title"]} {row["snippet"]} {row["url"]}\n'
                known = texts_by_link.get(row['url'])
                if known is not None:
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
            if len(hits) >= requested:
                capped = True
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
