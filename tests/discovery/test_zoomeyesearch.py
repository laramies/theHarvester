import asyncio
import base64
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import zoomeyesearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('zoomeye')
@pytest.mark.asyncio
async def test_process_reuses_session_and_collects_all_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    session = object()
    session_exited = False
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {
                'code': 60000,
                'total': 1,
                'data': [
                    {
                        'ip': '192.0.2.1',
                        'domain': 'api.example.com',
                        'hostname': 'host.example.com',
                        'asn': 64500,
                        'url': 'https://portal.example.com/v1',
                        'banner': 'admin@example.com',
                    }
                ],
            },
            200,
            {},
        )
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        assert kwargs == {
            'headers': {'API-KEY': 'test-key', 'Content-Type': 'application/json'},
            'proxy': True,
        }
        try:
            yield session
        finally:
            session_exited = True

    async def fake_post_fetch(*args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append({'url': args[0], **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = zoomeyesearch.SearchZoomEye('example.com', 2)
    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'host.example.com', 'portal.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}
    assert await search.get_asns() == {'AS64500'}
    assert await search.get_urls() == {'https://portal.example.com/v1'}
    assert await search.get_emails() == {'admin@example.com'}
    assert report is None
    assert [call['url'] for call in calls] == [search.baseurl]
    assert all(call['session'] is session for call in calls)
    assert session_exited is True
    assert base64.b64decode(calls[0]['json_body']['qbase64']).decode() == 'domain="example.com"'
    assert calls[0]['json_body']['page'] == 1
    assert calls[0]['json_body']['pagesize'] == 2


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        zoomeyesearch.SearchZoomEye('example.com', 1)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    with pytest.raises(ValueError, match='positive integer'):
        zoomeyesearch.SearchZoomEye('example.com', limit)


def test_explicit_www_target_is_not_widened(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))

    search = zoomeyesearch.SearchZoomEye('WWW.Example.COM.', 1)

    assert search.target == 'www.example.com'


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'code': 60001}, 200, {}), 'failed', 'provider-error'),
    ],
)
@pytest.mark.asyncio
async def test_provider_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = zoomeyesearch.SearchZoomEye('example.com', 1)
    report = await search.process()

    assert report.status == status
    assert report.stop_reason == reason


@pytest.mark.asyncio
async def test_empty_pages_do_not_hide_later_provider_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(
            {
                'code': 60000,
                'total': 70_000,
                'data': ([{'hostname': 'late.example.com'}] if page == 6 else []),
            },
            200,
            {},
        )
        for page in range(1, 8)
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = zoomeyesearch.SearchZoomEye('example.com', 70_000)
    report = await search.process()

    assert await search.get_hostnames() == {'late.example.com'}
    assert responses == []
    assert report is None


@pytest.mark.asyncio
async def test_unlimited_search_uses_provider_total(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse({'code': 60000, 'total': 2, 'data': [{'hostname': 'one.example.com'}]}, 200, {}),
        FetcherResponse({'code': 60000, 'total': 2, 'data': [{'hostname': 'two.example.com'}]}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['json_body'])
        return responses.pop(0)

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(zoomeyesearch.SearchZoomEye, 'PAGE_SIZE', 1)
    search = zoomeyesearch.SearchZoomEye('example.com', None)

    assert await search.process() is None
    assert [call['page'] for call in calls] == [1, 2]
    assert await search.get_hostnames() == {'one.example.com', 'two.example.com'}


@pytest.mark.asyncio
async def test_numbered_pages_keep_a_stable_size_and_slice_the_final_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['json_body'])
        return FetcherResponse({'code': 60000, 'total': 10_005, 'data': []}, 200, {})

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = zoomeyesearch.SearchZoomEye('example.com', 10_005)

    report = await search.process()

    assert report is None
    assert [(call['page'], call['pagesize']) for call in calls] == [(1, 10_000), (2, 10_000)]


@pytest.mark.asyncio
@pytest.mark.parametrize('malformed_match', [7, {'url': ['https://api.example.com']}])
async def test_early_malformed_rows_and_later_valid_evidence_are_partial(
    monkeypatch: pytest.MonkeyPatch,
    malformed_match: Any,
) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(zoomeyesearch.SearchZoomEye, 'PAGE_SIZE', 1)
    responses = [
        FetcherResponse({'code': 60000, 'total': 2, 'data': [malformed_match]}, 200, {}),
        FetcherResponse({'code': 60000, 'total': 2, 'data': [{'hostname': 'api.example.com'}]}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = zoomeyesearch.SearchZoomEye('example.com', 2)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_banner_urls_are_absolute_http_and_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    search = zoomeyesearch.SearchZoomEye('example.com', 1)
    banner = '\n'.join(
        f'"{value}"'
        for value in (
            'https://api.example.com/v1',
            '//example.com/path',
            '/assets/example.com/config.js',
            'https://evil.test/?target=example.com',
            'ftp://api.example.com/archive',
        )
    )

    _hostnames, _emails, _ips, _asns, urls, malformed = await search.parse_matches([{'banner': banner}])

    assert urls == {'https://api.example.com/v1'}
    assert malformed is False


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    session_exited = False

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield object()
        finally:
            session_exited = True

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'post_fetch', fake_post_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await zoomeyesearch.SearchZoomEye('example.com', 10).process()
    assert session_exited is True
