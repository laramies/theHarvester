from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import netlas
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.mark.provider_contract('netlas')
@pytest.mark.asyncio
async def test_process_uses_current_api_contract_and_keeps_scoped_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: 'test-key'))
    session = object()
    session_exited = False
    session_options: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            [
                {'data': {'domain': 'API.Example.COM.'}},
                {'data': {'domain': 'outside.test'}},
                {'data': {'domain': 'www.example.com'}},
            ],
            200,
            {},
        ),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        session_options.append(kwargs)
        try:
            yield session
        finally:
            session_exited = True

    async def fake_post_fetch(*args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append({'url': args[0], **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(netlas.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(netlas.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = netlas.SearchNetlas('example.com', limit=2)
    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com'}
    assert report is None
    assert session_options == [{'headers': {'Authorization': 'Bearer test-key'}, 'proxy': True}]
    assert calls[0]['url'] == 'https://app.netlas.io/api/domains/download/'
    assert calls[0]['session'] is session
    assert calls[0]['json_body'] == {
        'q': '*.example.com',
        'size': 2,
        'fields': ['domain'],
        'source_type': 'include',
    }
    assert session_exited is True


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        netlas.SearchNetlas('example.com', limit=10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: 'test-key'))
    with pytest.raises(ValueError, match='positive integer'):
        netlas.SearchNetlas('example.com', limit=limit)


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 402, {}), 'failed', 'quota-exhausted'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse(None, 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'count': 'many'}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_download_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: 'test-key'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(netlas.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(netlas.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = netlas.SearchNetlas('example.com', limit=10)

    report = await search.process()

    assert report.status == status
    assert report.stop_reason == reason


@pytest.mark.asyncio
async def test_malformed_download_rows_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse([{'data': {'domain': 'ok.example.com'}}, {'data': {'domain': 7}}], 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(netlas.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(netlas.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = netlas.SearchNetlas('example.com', limit=10)

    report = await search.process()

    assert await search.get_hostnames() == {'ok.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netlas.Core, 'netlas_key', staticmethod(lambda: 'test-key'))
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

    monkeypatch.setattr(netlas.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(netlas.AsyncFetcher, 'post_fetch', fake_post_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await netlas.SearchNetlas('example.com', limit=10).process()
    assert session_exited is True
