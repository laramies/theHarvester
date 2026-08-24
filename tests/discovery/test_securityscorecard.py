from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import securityscorecard
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.mark.provider_contract('securityscorecard')
@pytest.mark.asyncio
async def test_process_paginates_documented_domain_and_ip_asset_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(securityscorecard.SearchSecurityScorecard, 'PAGE_SIZE', 2)
    session = object()
    session_exited = False
    calls: list[dict[str, Any]] = []
    post_responses = [
        FetcherResponse(
            {'entries': [{'domain': 'API.Example.COM.'}, {'domain': 'outside.test'}], 'size': 3},
            200,
            {},
        ),
        FetcherResponse({'entries': [{'domain': 'www.example.com'}], 'size': 3}, 200, {}),
        FetcherResponse({'entries': [{'ip': '192.0.2.1'}, {'ip': '2001:db8::1'}], 'size': 3}, 200, {}),
        FetcherResponse({'entries': [{'ip': '198.51.100.2'}], 'size': 3}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        assert kwargs == {'headers': search.headers, 'proxy': True}
        try:
            yield session
        finally:
            session_exited = True

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return FetcherResponse({'score': 92, 'grade': 'A', 'factor_grades': {'network_security': 'A'}}, 200, {})

    async def fake_post_fetch(*args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append({'url': args[0], **kwargs})
        return post_responses.pop(0)

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = securityscorecard.SearchSecurityScorecard('example.com', 3)
    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert await search.get_ips() == {'192.0.2.1', '198.51.100.2', '2001:db8::1'}
    assert await search.get_score() == 92
    assert await search.get_grades() == {'overall': 'A', 'network_security': 'A'}
    assert report is None
    assert calls[0] == {
        'session': session,
        'url': 'https://api.securityscorecard.io/companies/example.com',
        'json': True,
        'include_metadata': True,
    }
    assert [(call['url'], call['json_body']) for call in calls[1:]] == [
        ('https://api.securityscorecard.io/parent-domains/example.com/domains', {'page': 0, 'page_size': 2}),
        ('https://api.securityscorecard.io/parent-domains/example.com/domains', {'page': 1, 'page_size': 2}),
        ('https://api.securityscorecard.io/parent-domains/example.com/ips', {'page': 0, 'page_size': 2}),
        ('https://api.securityscorecard.io/parent-domains/example.com/ips', {'page': 1, 'page_size': 2}),
    ]
    assert all(call['session'] is session for call in calls[1:])
    assert session_exited is True


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        securityscorecard.SearchSecurityScorecard('example.com', 10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))
    with pytest.raises(ValueError, match='positive integer'):
        securityscorecard.SearchSecurityScorecard('example.com', limit)


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 403, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_provider_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)
    search = securityscorecard.SearchSecurityScorecard('example.com', 10)
    report = await search.process()

    assert report.status == status
    assert report.stop_reason == reason


@pytest.mark.asyncio
async def test_malformed_asset_rows_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse({'entries': [{'domain': 7}, {'domain': 'api.example.com'}], 'size': 2}, 200, {}),
        FetcherResponse({'entries': [{'ip': 'not-an-ip'}, {'ip': '192.0.2.1'}], 'size': 2}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'score': 90, 'grade': 'A'}, 200, {})

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = securityscorecard.SearchSecurityScorecard('example.com', 2)
    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.parametrize(
    ('entry', 'expected_status', 'expected_hosts'),
    [
        ({'domain': 'api.example.com'}, 'partial', {'api.example.com'}),
        ({'domain': 'outside.test'}, 'failed', set()),
    ],
)
@pytest.mark.asyncio
async def test_unlimited_repeated_asset_page_stops_with_truthful_report(
    monkeypatch: pytest.MonkeyPatch,
    entry: dict[str, str],
    expected_status: str,
    expected_hosts: set[str],
) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(securityscorecard.SearchSecurityScorecard, 'PAGE_SIZE', 1)
    calls = 0

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({}, 200, {})

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return FetcherResponse({'entries': [entry], 'size': 2}, 200, {})

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = securityscorecard.SearchSecurityScorecard('example.com', None)

    report = await search.process()

    assert calls == 2
    assert await search.get_hostnames() == expected_hosts
    assert report.status == expected_status
    assert report.stop_reason == 'repeated-page'


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', staticmethod(lambda: 'test-key'))
    session_exited = False

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield object()
        finally:
            session_exited = True

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await securityscorecard.SearchSecurityScorecard('example.com', 10).process()
    assert session_exited is True
