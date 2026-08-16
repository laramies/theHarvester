from __future__ import annotations

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


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

    async def do_search(self) -> SourceExecutionReport | None:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        records_seen = 0
        report = None
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
                if error := provider_http_error(response):
                    return SourceExecutionReport(*error)
                assert isinstance(response, FetcherResponse)
                if not isinstance(response.body, dict):
                    return SourceExecutionReport('failed', 'invalid-response')
                result = response.body.get('result')
                if not isinstance(result, dict) or not isinstance(result.get('records'), list):
                    return SourceExecutionReport('failed', 'invalid-response')
                next_cursor = result.get('nextPageSearchAfter')
                if not isinstance(next_cursor, str):
                    return SourceExecutionReport('failed', 'invalid-response')

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
                    report = SourceExecutionReport('failed', 'invalid-response')
                if records_seen >= self.limit or not next_cursor:
                    break
                if next_cursor in seen_cursors:
                    return SourceExecutionReport('failed', 'repeated-cursor')
                seen_cursors.add(next_cursor)
                cursor = next_cursor
        return report

    async def get_hostnames(self) -> set[str]:
        return self.total_results

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
