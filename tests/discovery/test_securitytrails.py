from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import securitytrailssearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.mark.provider_contract('securityTrails')
@pytest.mark.asyncio
async def test_process_reuses_session_and_parses_scoped_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', staticmethod(lambda: 'test-key'))
    session = object()
    session_exited = False
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {
                'hostname': 'example.com',
                'current_dns': {
                    'a': {'values': [{'ip': '192.0.2.1'}]},
                    'aaaa': {'values': [{'ipv6': '2001:db8::1'}]},
                },
            },
            200,
            {},
        ),
        FetcherResponse({'subdomains': ['API', 'www', 7]}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        assert kwargs == {'headers': {'APIKEY': 'test-key', 'Accept': 'application/json'}, 'proxy': True}
        try:
            yield session
        finally:
            session_exited = True

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch', fake_fetch)
    search = securitytrailssearch.SearchSecuritytrail('example.com')
    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'
    assert [call['url'] for call in calls] == [
        'https://api.securitytrails.com/v1/domain/example.com',
        'https://api.securitytrails.com/v1/domain/example.com/subdomains',
    ]
    assert all(call['session'] is session for call in calls)
    assert session_exited is True


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        securitytrailssearch.SearchSecuritytrail('example.com')


@pytest.mark.asyncio
async def test_required_proxy_unavailable_returns_explicit_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, '_proxy_list', {'http': [], 'socks5': []})

    report = await securitytrailssearch.SearchSecuritytrail('example.com').process(proxy=True)

    assert report == securitytrailssearch.SourceExecutionReport('failed', 'proxy-unavailable')


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_first_request_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', staticmethod(lambda: 'test-key'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch', fake_fetch)
    search = securitytrailssearch.SearchSecuritytrail('example.com')
    report = await search.process()

    assert report.status == status
    assert report.stop_reason == reason


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', staticmethod(lambda: 'test-key'))
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

    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await securitytrailssearch.SearchSecuritytrail('example.com').process()
    assert session_exited is True
