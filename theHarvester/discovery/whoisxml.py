from __future__ import annotations

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchWhoisXML:
    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('WhoisXML limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.key = Core.whoisxml_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('whoisxml')
        self.total_results: set[str] = set()
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.total_results else status
        self.stop_reason = reason

    async def do_search(self) -> None:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        records_seen = 0
        async with AsyncFetcher.open_session(proxy=self.proxy) as session:
            while records_seen < self.limit:
                params = {'apiKey': self.key, 'domainName': self.word}
                if cursor is not None:
                    params['searchAfter'] = cursor
                response = await AsyncFetcher.fetch(
                    session=session,
                    url='https://subdomains.whoisxmlapi.com/api/v2',
                    params=params,
                    json=True,
                    include_metadata=True,
                )
                if not isinstance(response, FetcherResponse):
                    self._stop('failed', 'transport-error')
                    return
                if response.status in {401, 403}:
                    self._stop('failed', 'access-denied')
                    return
                if response.status == 429:
                    self._stop('rate-limited', 'http-429')
                    return
                if not 200 <= response.status < 300:
                    self._stop('failed', f'http-{response.status}')
                    return
                if not isinstance(response.body, dict):
                    self._stop('failed', 'invalid-response')
                    return
                result = response.body.get('result')
                if not isinstance(result, dict) or not isinstance(result.get('records'), list):
                    self._stop('failed', 'invalid-response')
                    return
                next_cursor = result.get('nextPageSearchAfter')
                if not isinstance(next_cursor, str):
                    self._stop('failed', 'invalid-response')
                    return

                remaining = self.limit - records_seen
                records = result['records'][:remaining]
                records_seen += len(records)
                malformed = False
                for record in records:
                    if not isinstance(record, dict) or not isinstance(record.get('domain'), str):
                        malformed = True
                        continue
                    if hostname := normalize_scoped_hostname(record['domain'], self.word):
                        self.total_results.add(hostname)
                if malformed:
                    self._stop('failed', 'invalid-response')
                if records_seen >= self.limit or not next_cursor:
                    break
                if next_cursor in seen_cursors:
                    self._stop('failed', 'repeated-cursor')
                    break
                seen_cursors.add(next_cursor)
                cursor = next_cursor
        if self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self.total_results else 'no-results'

    async def get_hostnames(self) -> set[str]:
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        try:
            await self.do_search()
        except Exception:
            self._stop('failed', 'transport-error')
