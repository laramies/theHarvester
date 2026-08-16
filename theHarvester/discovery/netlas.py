from __future__ import annotations

from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


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

    @staticmethod
    def _response_body(response: Any) -> tuple[Any | None, SourceExecutionReport | None]:
        if isinstance(response, FetcherResponse) and response.status == 402:
            return None, SourceExecutionReport('failed', 'quota-exhausted')
        if error := provider_http_error(response):
            return None, SourceExecutionReport(*error)
        assert isinstance(response, FetcherResponse)
        if response.body is None:
            return None, SourceExecutionReport('failed', 'invalid-response')
        return response.body, None

    async def do_search(self, session: Any, size: int) -> SourceExecutionReport | None:
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
        body, report = self._response_body(response)
        if report is not None:
            return report
        if not isinstance(body, list):
            return SourceExecutionReport('failed', 'invalid-response')

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
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            async with AsyncFetcher.open_session(
                headers={'Authorization': f'Bearer {self.key}'},
                proxy=proxy,
            ) as session:
                return await self.do_search(session, self.limit)
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
