from __future__ import annotations

import json

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_hostname, normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchProfundis:
    URL = 'https://api.profundis.io/api/v2/common/data/subdomains'

    def __init__(self, word: str, limit: int | None) -> None:
        self.word = normalize_hostname(word)
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('Profundis limit must be a positive integer or None')
        self.limit = limit
        self.key = Core.profundis_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('profundis')
        self.max_credits = Core.profundis_max_credits()
        if isinstance(self.max_credits, bool) or not isinstance(self.max_credits, int) or not 1 <= self.max_credits <= 100000:
            raise ValueError('Profundis max_credits must be an integer between 1 and 100000')
        self.totalhosts: set[str] = set()

    @staticmethod
    def _control(line: str) -> SourceExecutionReport | None:
        try:
            record = json.loads(line)
        except ValueError, RecursionError:
            return SourceExecutionReport('failed', 'invalid-response')
        if not isinstance(record, dict):
            return SourceExecutionReport('failed', 'invalid-response')
        if record.get('code') == 'Q2014':
            return SourceExecutionReport('failed', 'quota-exhausted')
        if record.get('code') == 'Q2015':
            return SourceExecutionReport('partial', 'usage-limit')
        if any(field in record for field in ('code', 'error', 'notice')):
            return SourceExecutionReport('failed', 'provider-error')
        if record.get('type') != 'credits':
            return SourceExecutionReport('failed', 'invalid-response')
        if record.get('capped') is True:
            return SourceExecutionReport('partial', 'credit-limit')
        return None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        report = None
        try:
            async with AsyncFetcher.stream_records(
                self.URL,
                method='POST',
                # Despite its content type, this API emits lines, not SSE data: events.
                framing='ndjson',
                headers={'X-API-KEY': self.key.strip(), 'Accept': 'text/event-stream'},
                json_body={'domain': self.word, 'max_credits': self.max_credits, 'source': 'theHarvester'},
                proxy=proxy,
            ) as response:
                if response.status == 402:
                    return SourceExecutionReport('failed', 'quota-exhausted')
                if error := provider_http_error(FetcherResponse(None, response.status, response.headers)):
                    return SourceExecutionReport(*error)
                async for raw in response:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith(('{', '[')):
                        if control := self._control(line):
                            # A later credit snapshot must not hide an earlier error.
                            if report is None or control.status == 'failed':
                                report = control
                        continue
                    try:
                        hostname = normalize_hostname(line)
                    except ValueError:
                        report = SourceExecutionReport('failed', 'invalid-response')
                        continue
                    if normalize_scoped_hostname(hostname, self.word) and (
                        self.limit is None or len(self.totalhosts) < self.limit
                    ):
                        self.totalhosts.add(hostname)
                # Drain the stream: errors may follow the final credit snapshot.
        except ResponseStreamError as error:
            return SourceExecutionReport('failed', error.reason)
        if report is not None:
            return report
        if self.limit is not None and len(self.totalhosts) >= self.limit:
            return SourceExecutionReport('completed', 'result-limit')
        return None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts
