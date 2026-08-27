import asyncio
from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchXquik:
    """Collect public X post URLs that match an authorized target.

    API docs: https://docs.xquik.com/api-reference/x/search-tweets
    """

    SEARCH_URL = 'https://xquik.com/api/v1/x/tweets/search'
    PAGE_SIZE = 500
    REQUEST_TIMEOUT_SECONDS = 60
    MAX_CURSOR_LENGTH = 8192
    MAX_RETRY_DELAY_SECONDS = 60

    def __init__(self, word: str, limit: int | None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('Xquik limit must be a positive integer')
        key = Core.xquik_key()
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('xquik')
        self.key = key.strip()
        self.word = word
        self.limit = limit
        self.proxy: bool | str = False
        self.urls: set[str] = set()
        self._seen_tweet_ids: set[str] = set()

    @staticmethod
    def _status_url(tweet_id: object) -> str | None:
        if not isinstance(tweet_id, str):
            return None
        value = tweet_id.strip()
        if not value or len(value) > 32 or not value.isascii() or not value.isdecimal():
            return None
        return f'https://x.com/i/web/status/{value}'

    @classmethod
    def _retry_delay(cls, response: FetcherResponse) -> int:
        value = response.headers.get('retry-after', '')
        if not value.isascii() or not value.isdecimal():
            return 1
        return min(int(value), cls.MAX_RETRY_DELAY_SECONDS)

    def _request_params(self, cursor: str | None) -> dict[str, int | str]:
        page_size = min(self.limit or self.PAGE_SIZE, self.PAGE_SIZE)
        params: dict[str, int | str] = {
            'q': self.word,
            'queryType': 'Latest',
            'limit': page_size,
        }
        if cursor is not None:
            params['cursor'] = cursor
        return params

    def _collect_page(self, tweets: list[Any]) -> bool:
        malformed = False
        for tweet in tweets:
            if not isinstance(tweet, dict) or (status_url := self._status_url(tweet.get('id'))) is None:
                malformed = True
                continue
            tweet_id = status_url.rsplit('/', 1)[-1]
            if tweet_id in self._seen_tweet_ids:
                continue
            self._seen_tweet_ids.add(tweet_id)
            if self.limit is None or len(self.urls) < self.limit:
                self.urls.add(status_url)
        return malformed

    def _incomplete(self, reason: str) -> SourceExecutionReport:
        return SourceExecutionReport('partial' if self.urls else 'failed', reason)

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'x-api-key': self.key}
        cursor: str | None = None
        seen_cursors: set[str] = set()
        restarted_cursor = False
        retry_count = 0
        malformed = False
        try:
            async with AsyncFetcher.open_session(
                headers=headers,
                proxy=self.proxy,
                request_timeout=self.REQUEST_TIMEOUT_SECONDS,
            ) as session:
                while True:
                    response = await AsyncFetcher.fetch_json(
                        self.SEARCH_URL,
                        session=session,
                        params=self._request_params(cursor),
                        request_timeout=self.REQUEST_TIMEOUT_SECONDS,
                    )
                    if response.status in {400, 410} and cursor is not None:
                        if restarted_cursor:
                            return self._incomplete('invalid-cursor' if response.status == 400 else 'cursor-expired')
                        cursor = None
                        seen_cursors.clear()
                        restarted_cursor = True
                        retry_count = 0
                        continue
                    retryable = response.status in {424, 429, 502, 503} or (response.status == 409 and cursor is not None)
                    if retryable and retry_count == 0:
                        retry_count = 1
                        await asyncio.sleep(self._retry_delay(response))
                        continue
                    if response.status == 409:
                        return self._incomplete('cursor-busy')
                    if failure := provider_http_error(response):
                        return SourceExecutionReport(*failure)
                    if not isinstance(response.body, dict):
                        return self._incomplete('invalid-response')
                    tweets = response.body.get('tweets')
                    has_next_page = response.body.get('has_next_page')
                    if not isinstance(tweets, list) or not isinstance(has_next_page, bool):
                        return self._incomplete('invalid-response')
                    malformed |= self._collect_page(tweets)
                    if self.limit is not None and len(self.urls) >= self.limit:
                        return (
                            self._incomplete('invalid-response')
                            if malformed
                            else SourceExecutionReport('completed', 'result-limit')
                        )
                    if not has_next_page:
                        return self._incomplete('invalid-response') if malformed else None
                    next_cursor = response.body.get('next_cursor')
                    if (
                        not isinstance(next_cursor, str)
                        or not next_cursor
                        or len(next_cursor) > self.MAX_CURSOR_LENGTH
                        or not next_cursor.isprintable()
                    ):
                        return self._incomplete('invalid-response')
                    if next_cursor in seen_cursors:
                        return self._incomplete('repeated-cursor')
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
                    retry_count = 0
        except asyncio.CancelledError:
            raise
        except ResponseStreamError as error:
            return self._incomplete(error.reason)
        except Exception:
            return self._incomplete('transport-error')

    async def get_urls(self) -> set[str]:
        return self.urls

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
