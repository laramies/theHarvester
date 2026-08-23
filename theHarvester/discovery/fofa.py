import base64
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchFofa:
    """Collect scoped domain assets through FOFA's cursor search API."""

    MAX_PAGE_SIZE = 10_000

    def __init__(self, word: str, limit: int | None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('FOFA limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.proxy = False
        self.hostname = 'https://fofa.info'
        self.api_key, self.email = self._get_api_credentials()

    def _get_api_credentials(self) -> tuple[str, str]:
        try:
            api_key, email = Core.fofa_key()
        except Exception as error:
            raise MissingKey('Fofa API (key and email required)') from error
        if not all(isinstance(value, str) and value.strip() for value in (api_key, email)):
            raise MissingKey('Fofa API (key and email required)')
        return api_key, email

    def _store_results(self, results: list[Any]) -> bool:
        malformed = False
        for result in results:
            if not isinstance(result, list) or len(result) < 2:
                malformed = True
                continue
            host, address = result[:2]
            if isinstance(host, str):
                try:
                    parsed_hostname = urlparse(host if '://' in host else f'//{host}').hostname
                except ValueError:
                    malformed = True
                else:
                    if clean_host := normalize_scoped_hostname(parsed_hostname, self.word):
                        self.totalhosts.add(clean_host)
            else:
                malformed = True
            if isinstance(address, str):
                try:
                    self.totalips.add(str(ip_address(address)))
                except ValueError:
                    malformed = True
            else:
                malformed = True
        return malformed

    def _provider_error(self, body: dict[str, Any]) -> SourceExecutionReport:
        message = body.get('errmsg')
        normalized = message.casefold() if isinstance(message, str) else ''
        if 'invalid' in normalized or '账号无效' in normalized:
            return SourceExecutionReport('failed', 'access-denied')
        if any(term in normalized for term in ('quota', 'limit', 'plan')):
            return SourceExecutionReport('failed', 'quota-exhausted')
        return SourceExecutionReport('failed', 'provider-error')

    async def do_search(self) -> SourceExecutionReport | None:
        query = base64.b64encode(f'domain="{self.word}"'.encode()).decode()
        cursor: str | None = None
        seen_cursors: set[str] = set()
        records_seen = 0
        report = None
        try:
            async with AsyncFetcher.open_session(
                headers={'User-Agent': Core.get_user_agent()},
                proxy=self.proxy,
            ) as session:
                while self.limit is None or records_seen < self.limit:
                    remaining = self.limit - records_seen if self.limit is not None else self.MAX_PAGE_SIZE
                    params: dict[str, str | int] = {
                        'email': self.email,
                        'key': self.api_key,
                        'qbase64': query,
                        'fields': 'host,ip',
                        'size': min(self.MAX_PAGE_SIZE, remaining),
                    }
                    if cursor is not None:
                        params['next'] = cursor
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url=f'{self.hostname}/api/v1/search/next',
                        params=params,
                        json=True,
                        include_metadata=True,
                    )
                    if error := provider_http_error(response):
                        return SourceExecutionReport(*error)
                    assert isinstance(response, FetcherResponse)
                    if not isinstance(response.body, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    if response.body.get('error') is True:
                        return self._provider_error(response.body)
                    results = response.body.get('results')
                    if not isinstance(results, list):
                        return SourceExecutionReport('failed', 'invalid-response')

                    page_results = results[:remaining] if self.limit is not None else results
                    records_seen += len(page_results)
                    if self._store_results(page_results):
                        report = SourceExecutionReport('failed', 'invalid-response')
                    next_cursor = response.body.get('next')
                    if not results or not isinstance(next_cursor, str) or not next_cursor:
                        break
                    if next_cursor in seen_cursors:
                        return SourceExecutionReport(
                            'partial' if self.totalhosts or self.totalips else 'failed',
                            'repeated-cursor',
                        )
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
        return report

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
