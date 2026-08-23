import asyncio
from typing import Any

import pytest

from theHarvester.discovery import mojeek
from theHarvester.lib.core import FetcherResponse


class TestMojeekSearch:
    @pytest.mark.asyncio
    async def test_unlimited_keyless_stops_when_provider_repeats_a_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []
        responses = iter(
            [
                FetcherResponse(body='<ul class="results-standard">one.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='<ul class="results-standard">two.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='<ul class="results-standard">two.example.com</ul>', status=200, headers={}),
            ]
        )

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return next(responses)

        async def fake_sleep(_delay: float) -> None:
            return None

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=None)

        report = await search.process()

        assert report == mojeek.SourceExecutionReport('partial', 'repeated-page')
        assert [call['url'] for call in calls] == [
            'https://www.mojeek.com/search?q=example.com&s=0',
            'https://www.mojeek.com/search?q=example.com&s=10',
            'https://www.mojeek.com/search?q=example.com&s=20',
        ]
        assert await search.get_hostnames() == ['one.example.com', 'two.example.com']

    @pytest.mark.asyncio
    async def test_unlimited_keyed_api_stops_when_provider_exhausts_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requests: list[list[str]] = []
        responses = iter(
            [
                FetcherResponse(body={'response': {'results': [{'url': 'https://one.example.com'}]}}, status=200, headers={}),
                FetcherResponse(body={'response': {'results': [{'url': 'https://two.example.com'}]}}, status=200, headers={}),
                FetcherResponse(body={'response': {'results': []}}, status=200, headers={}),
            ]
        )

        async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
            requests.append(urls)
            return [next(responses)]

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = mojeek.SearchMojeek(word='example.com', limit=None)

        report = await search.process()

        assert report is None
        assert requests == [
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1'],
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11'],
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=21'],
        ]
        assert await search.get_hostnames() == ['one.example.com', 'two.example.com']

    @pytest.mark.asyncio
    async def test_unlimited_keyed_api_reports_repeated_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        page = FetcherResponse(
            body={'response': {'results': [{'url': 'https://one.example.com'}]}},
            status=200,
            headers={},
        )

        async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
            return [page]

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)

        report = await mojeek.SearchMojeek(word='example.com', limit=None).process()

        assert report == mojeek.SourceExecutionReport('partial', 'repeated-page')

    @pytest.mark.asyncio
    async def test_keyless_later_http_failure_is_partial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = iter(
            [
                FetcherResponse(body='<ul class="results-standard">one.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='unavailable', status=503, headers={}),
            ]
        )

        async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
            return next(responses)

        async def fake_sleep(_delay: float) -> None:
            return None

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)

        report = await mojeek.SearchMojeek(word='example.com', limit=None).process()

        assert report == mojeek.SourceExecutionReport('partial', 'http-503')

    @pytest.mark.asyncio
    async def test_mojeek_cancellation_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def cancel(**_kwargs: Any) -> FetcherResponse:
            raise asyncio.CancelledError('operator-stop')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', cancel)

        with pytest.raises(asyncio.CancelledError, match='operator-stop'):
            await mojeek.SearchMojeek(word='example.com', limit=None).process()

    @pytest.mark.asyncio
    async def test_keyless_pages_are_sequential_and_stop_after_first_empty_page(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[dict[str, Any]] = []
        delays: list[float] = []
        responses = iter(
            [
                FetcherResponse(
                    body='<ul class="results-standard"><li>docs.example.com admin@example.com</li></ul>',
                    status=200,
                    headers={},
                ),
                FetcherResponse(body='<html>No results found</html>', status=200, headers={}),
                FetcherResponse(body='<html>must-not-run.example.com</html>', status=200, headers={}),
            ]
        )

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return next(responses)

        async def fake_sleep(delay: float) -> None:
            delays.append(delay)

        async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
            raise AssertionError('keyless Mojeek pages must be requested sequentially')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', reject_fetch_all)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=30)

        report = await search.process(proxy=True)

        assert [call['url'] for call in calls] == [
            'https://www.mojeek.com/search?q=example.com&s=0',
            'https://www.mojeek.com/search?q=example.com&s=10',
        ]
        assert all(call['include_metadata'] is True for call in calls)
        assert all(call['headers'] == {'User-Agent': 'UA'} for call in calls)
        assert all(call['follow_redirects'] is False for call in calls)
        assert all(call['proxy'] is True for call in calls)
        assert delays == [1.0]
        assert await search.get_hostnames() == ['docs.example.com', 'example.com']
        assert await search.get_emails() == {'admin@example.com'}
        assert report is None

    @pytest.mark.parametrize(
        ('http_status', 'execution_status', 'stop_reason'),
        [(403, 'failed', 'access-denied'), (429, 'rate-limited', 'http-429')],
    )
    @pytest.mark.asyncio
    async def test_keyless_http_denial_is_attributed_before_pagination(
        self,
        monkeypatch: pytest.MonkeyPatch,
        http_status: int,
        execution_status: str,
        stop_reason: str,
    ) -> None:
        calls: list[dict[str, Any]] = []
        delays: list[float] = []

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return FetcherResponse(body='<html>Access denied</html>', status=http_status, headers={})

        async def fake_sleep(delay: float) -> None:
            delays.append(delay)

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=30)

        report = await search.process()

        assert len(calls) == 1
        assert calls[0]['follow_redirects'] is False
        assert delays == []
        assert report.status == execution_status
        assert report.stop_reason == stop_reason
        assert await search.get_hostnames() == []

    @pytest.mark.parametrize(
        ('body', 'execution_status', 'stop_reason'),
        [
            ('<html>Maintenance</html>', 'failed', 'invalid-response'),
            ('<html>Access denied</html>', 'failed', 'access-denied'),
            ('<html>Please complete the CAPTCHA</html>', 'failed', 'security-verification'),
        ],
    )
    @pytest.mark.asyncio
    async def test_keyless_200_error_pages_are_not_completed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        body: str,
        execution_status: str,
        stop_reason: str,
    ) -> None:
        async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
            return FetcherResponse(body=body, status=200, headers={})

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        search = mojeek.SearchMojeek(word='example.com', limit=10)

        report = await search.process()

        assert report.status == execution_status
        assert report.stop_reason == stop_reason
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_failed_keyed_api_does_not_fall_back_to_scraping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []

        async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
            calls.append({'urls': urls, **kwargs})
            return [FetcherResponse(body={'status': 'Access denied'}, status=403, headers={})]

        async def reject_scrape(**_kwargs: Any) -> FetcherResponse:
            raise AssertionError('failed keyed API calls must not fall back to scraping')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', reject_scrape)
        search = mojeek.SearchMojeek(word='example.com', limit=10)

        report = await search.process(proxy=True)

        assert len(calls) == 1
        assert calls[0]['include_metadata'] is True
        assert calls[0]['proxy'] is True
        assert report.status == 'failed'
        assert report.stop_reason == 'access-denied'
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_keyed_api_success_parses_results_without_scraping(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        requests: list[dict[str, Any]] = []

        async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
            requests.append({'urls': urls, **kwargs})
            return [
                FetcherResponse(
                    status=200,
                    headers={},
                    body={
                        'response': {
                            'results': [
                                {
                                    'url': 'https:\\/\\/Blog.Example.COM.\\/contact',
                                    'title': 'Contact Admin@Example.COM.',
                                    'desc': 'API docs at api.example.com; ignore outsider@example.net',
                                }
                            ]
                        }
                    },
                ),
                FetcherResponse(body={'response': {'results': []}}, status=200, headers={}),
            ]

        async def reject_scrape(**_kwargs: Any) -> FetcherResponse:
            raise AssertionError('successful keyed API calls must not scrape')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', reject_scrape)

        search = mojeek.SearchMojeek(word='example.com', limit=20)
        report = await search.process(proxy=True)

        assert requests == [
            {
                'urls': [
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1',
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11',
                ],
                'headers': {'User-Agent': 'UA'},
                'proxy': True,
                'json': True,
                'include_metadata': True,
            }
        ]
        assert await search.get_emails() == {'admin@example.com'}
        assert set(await search.get_hostnames()) - {'example.com'} == {
            'api.example.com',
            'blog.example.com',
        }
        assert report is None


pytestmark = pytest.mark.provider_contract('mojeek')
