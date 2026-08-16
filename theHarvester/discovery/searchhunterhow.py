import asyncio
import base64
from datetime import UTC, datetime
from typing import Any

from dateutil.relativedelta import relativedelta

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchHunterHow:
    REQUEST_DELAY_SECONDS = 2.0

    def __init__(self, word: str, limit: int = 500) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('Hunter.how limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.total_hostnames: set[str] = set()
        self.key = Core.hunterhow_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('hunterhow')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.total_hostnames else status
        self.stop_reason = reason

    @staticmethod
    def _page_size(remaining: int) -> int:
        for size in (10, 20, 50, 100, 1000):
            if remaining <= size:
                return size
        return 1000

    async def do_search(self) -> None:
        self.execution_status = None
        self.stop_reason = None
        query = base64.urlsafe_b64encode(f'domain.suffix="{self.word}"'.encode()).decode('ascii')
        end = datetime.now(UTC).date()
        start = end - relativedelta(days=364)
        page = 1
        returned = 0
        params: dict[str, Any] = {
            'api-key': self.key,
            'query': query,
            'start_time': start.isoformat(),
            'end_time': end.isoformat(),
            'fields': 'domain',
        }
        try:
            async with AsyncFetcher.open_session(
                headers={'User-Agent': Core.get_user_agent()},
                proxy=self.proxy,
            ) as session:
                while returned < self.limit:
                    request_params = {
                        **params,
                        'page': page,
                        'page_size': self._page_size(self.limit - returned),
                    }
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url='https://api.hunter.how/search',
                        params=request_params,
                        include_metadata=True,
                    )
                    if error := provider_http_error(response):
                        self._stop(*error)
                        return
                    assert isinstance(response, FetcherResponse)
                    if not isinstance(response.body, dict):
                        self._stop('failed', 'invalid-response')
                        return
                    code = response.body.get('code')
                    if code == 40001:
                        self._stop('failed', 'access-denied')
                        return
                    if code != 200:
                        self._stop('failed', 'provider-error')
                        return
                    data = response.body.get('data')
                    if not isinstance(data, dict):
                        self._stop('failed', 'invalid-response')
                        return
                    total = data.get('total')
                    rows = data.get('list')
                    if isinstance(total, bool) or not isinstance(total, int) or total < 0 or not isinstance(rows, list):
                        self._stop('failed', 'invalid-response')
                        return

                    remaining = self.limit - returned
                    malformed = False
                    for row in rows[:remaining]:
                        if not isinstance(row, dict) or not isinstance(row.get('domain'), str):
                            malformed = True
                            continue
                        if hostname := normalize_scoped_hostname(row['domain'], self.word):
                            self.total_hostnames.add(hostname)
                    if malformed:
                        self._stop('failed', 'invalid-response')

                    returned += len(rows)
                    if not rows or returned >= min(total, self.limit):
                        break
                    page += 1
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
        except Exception:
            self._stop('failed', 'transport-error')
            return

        if self.execution_status is not None and self.total_hostnames:
            self.execution_status = 'partial'
        elif self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self.total_hostnames else 'no-results'

    async def get_hostnames(self) -> set[str]:
        return self.total_hostnames

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
