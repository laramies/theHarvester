import asyncio
from typing import Any

import pytest

from theHarvester.discovery import yahoosearch
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
async def test_yahoo_uses_exact_pages_and_normalizes_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, Any]] = []

    async def fake_fetch_all(
        urls: list[str] | set[str],
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> list[str]:
        requests.append({'urls': list(urls), 'headers': headers, 'proxy': proxy})
        return [
            'Contact Admin@Example.COM. at Blog.Example.COM.',
            'Ignore outsider@example.net and api.example.net',
        ]

    monkeypatch.setattr(yahoosearch.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = yahoosearch.SearchYahoo('example.com', 20)
    await search.process(proxy=True)

    assert requests == [
        {
            'urls': [
                'https://search.yahoo.com/search?p=%40example.com&b=0&pz=10',
                'https://search.yahoo.com/search?p=%40example.com&b=10&pz=10',
            ],
            'headers': {'Host': 'search.yahoo.com', 'User-Agent': 'UA'},
            'proxy': True,
        }
    ]
    assert set(await search.get_emails()) == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.asyncio
async def test_yahoo_unlimited_stops_when_provider_repeats_a_page(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, Any]] = []
    responses = iter(['one.example.com', 'two.example.com', 'two.example.com'])

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requests.append(kwargs)
        return FetcherResponse(next(responses), 200, {})

    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch', fake_fetch)
    search = yahoosearch.SearchYahoo('example.com', None)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'repeated-page')
    assert [request['url'] for request in requests] == [
        'https://search.yahoo.com/search?p=%40example.com&b=0&pz=10',
        'https://search.yahoo.com/search?p=%40example.com&b=10&pz=10',
        'https://search.yahoo.com/search?p=%40example.com&b=20&pz=10',
    ]
    assert await search.get_hostnames() == ['one.example.com', 'two.example.com']


@pytest.mark.parametrize(
    ('response', 'expected_report'),
    [
        ('', None),
        (None, SourceExecutionReport('failed', 'transport-error')),
        (FetcherResponse({}, 200, {}), SourceExecutionReport('failed', 'invalid-response')),
        ('<html>Access denied at api.example.net</html>', SourceExecutionReport('failed', 'access-denied')),
    ],
    ids=['empty', 'missing', 'malformed', 'blocked'],
)
@pytest.mark.asyncio
async def test_yahoo_unusable_responses_return_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    expected_report: SourceExecutionReport | None,
) -> None:
    async def fake_fetch_all(urls: list[str] | set[str], **_kwargs: Any) -> list[object]:
        return [response] * len(urls)

    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = yahoosearch.SearchYahoo('example.com', 20)
    report = await search.process()

    assert report == expected_report
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []


@pytest.mark.asyncio
async def test_yahoo_later_http_failure_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse('one.example.com', 200, {}),
            FetcherResponse('unavailable', 503, {}),
        ]

    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    report = await yahoosearch.SearchYahoo('example.com', 20).process()

    assert report == SourceExecutionReport('partial', 'http-503')


@pytest.mark.asyncio
async def test_yahoo_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancel(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch', cancel)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await yahoosearch.SearchYahoo('example.com', None).process()


pytestmark = pytest.mark.provider_contract('yahoo')
