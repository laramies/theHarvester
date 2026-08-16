from __future__ import annotations

from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchNetlas:
    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('Netlas limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.totalhosts: set[str] = set()
        self.key = Core.netlas_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('netlas')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.totalhosts else status
        self.stop_reason = reason

    def _response_body(self, response: Any) -> Any | None:
        if isinstance(response, FetcherResponse) and response.status == 402:
            self._stop('failed', 'quota-exhausted')
            return None
        if error := provider_http_error(response):
            self._stop(*error)
            return None
        assert isinstance(response, FetcherResponse)
        if response.body is None:
            self._stop('failed', 'invalid-response')
            return None
        return response.body

    async def do_search(self, session: Any, size: int) -> None:
        response = await AsyncFetcher.post_fetch(
            'https://app.netlas.io/api/domains/download/',
            session=session,
            json=True,
            include_metadata=True,
            json_body={
                'q': f'*.{self.word}',
                'size': size,
                'fields': ['domain'],
                'source_type': 'include',
            },
        )
        body = self._response_body(response)
        if body is None:
            return
        if not isinstance(body, list):
            self._stop('failed', 'invalid-response')
            return

        malformed = False
        for row in body[:size]:
            if not isinstance(row, dict) or not isinstance(row.get('data'), dict):
                malformed = True
                continue
            domain = row['data'].get('domain')
            if not isinstance(domain, str):
                malformed = True
                continue
            if hostname := normalize_scoped_hostname(domain, self.word):
                self.totalhosts.add(hostname)
        if malformed:
            self._stop('failed', 'invalid-response')

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        try:
            async with AsyncFetcher.open_session(
                headers={'Authorization': f'Bearer {self.key}'},
                proxy=proxy,
            ) as session:
                await self.do_search(session, self.limit)
        except Exception:
            self._stop('failed', 'transport-error')
            return
        if self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self.totalhosts else 'no-results'
