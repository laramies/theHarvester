import asyncio
import base64
from datetime import UTC, date, datetime
from typing import Any

from dateutil.relativedelta import relativedelta

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchHunterHow:
    REQUEST_DELAY_SECONDS = 2.0
    ALL_HISTORY_START = date(1970, 1, 1)

    def __init__(self, word: str, limit: int | None = 500) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('Hunter.how limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.total_hostnames: set[str] = set()
        self.key = Core.hunterhow_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('hunterhow')
        self.proxy = False

    @staticmethod
    def _page_size(remaining: int) -> int:
        for size in (10, 20, 50, 100, 1000):
            if remaining <= size:
                return size
        return 1000

    async def do_search(self) -> SourceExecutionReport | None:
        query = base64.urlsafe_b64encode(f'domain.suffix="{self.word}"'.encode()).decode('ascii')
        end = datetime.now(UTC).date()
        start = self.ALL_HISTORY_START if self.limit is None else end - relativedelta(days=364)
        page = 1
        returned = 0
        params: dict[str, Any] = {
            'api-key': self.key,
            'query': query,
            'start_time': start.isoformat(),
            'end_time': end.isoformat(),
            'fields': 'domain',
        }
        report = None
        try:
            async with AsyncFetcher.open_session(
                headers={'User-Agent': Core.get_user_agent()},
                proxy=self.proxy,
            ) as session:
                while self.limit is None or returned < self.limit:
                    request_params = {
                        **params,
                        'page': page,
                        'page_size': self._page_size(self.limit - returned) if self.limit is not None else 1000,
                    }
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url='https://api.hunter.how/search',
                        params=request_params,
                        include_metadata=True,
                    )
                    if error := provider_http_error(response):
                        return SourceExecutionReport(*error)
                    assert isinstance(response, FetcherResponse)
                    if not isinstance(response.body, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    code = response.body.get('code')
                    if code == 40001:
                        return SourceExecutionReport('failed', 'access-denied')
                    if code != 200:
                        return SourceExecutionReport('failed', 'provider-error')
                    data = response.body.get('data')
                    if not isinstance(data, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    total = data.get('total')
                    rows = data.get('list')
                    if isinstance(total, bool) or not isinstance(total, int) or total < 0 or not isinstance(rows, list):
                        return SourceExecutionReport('failed', 'invalid-response')

                    remaining = self.limit - returned if self.limit is not None else len(rows)
                    malformed = False
                    for row in rows[:remaining]:
                        if not isinstance(row, dict) or not isinstance(row.get('domain'), str):
                            malformed = True
                            continue
                        if hostname := normalize_scoped_hostname(row['domain'], self.word):
                            self.total_hostnames.add(hostname)
                    if malformed:
                        report = SourceExecutionReport('failed', 'invalid-response')

                    returned += len(rows)
                    if not rows or returned >= (min(total, self.limit) if self.limit is not None else total):
                        break
                    page += 1
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
        return report

    async def get_hostnames(self) -> set[str]:
        return self.total_hostnames

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
