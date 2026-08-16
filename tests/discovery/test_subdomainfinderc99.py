import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import subdomainfinderc99
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_successful_response_returns_only_scoped_hostnames(monkeypatch) -> None:
    session = object()
    session_exited = False
    calls: list[tuple[str, object]] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield session
        finally:
            session_exited = True

    async def fake_fetch(*_args, **kwargs):
        calls.append(('get', kwargs['session']))
        return FetcherResponse('<div class="input-group"><input name="token" value="abc"></div>', 200, {})

    async def fake_post_fetch(*_args, **kwargs):
        calls.append(('post', kwargs['session']))
        return FetcherResponse('api.example.test www.notexample.test', 200, {})

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(subdomainfinderc99.asyncio, 'sleep', no_sleep)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert set(await search.get_hostnames()) == {'api.example.test'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None
    assert calls == [('get', session), ('post', session)]
    assert session_exited is True


@pytest.mark.asyncio
async def test_empty_initial_response_is_transport_failure(monkeypatch) -> None:
    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(*_args, **_kwargs):
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert not await search.get_hostnames()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_malformed_scan_response_completes_without_evidence(monkeypatch) -> None:
    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(*_args, **_kwargs):
        return FetcherResponse('<div class="input-group"><input name="token" value="abc"></div>', 200, {})

    async def fake_post_fetch(*_args, **_kwargs):
        return FetcherResponse(None, 200, {})

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(subdomainfinderc99.asyncio, 'sleep', no_sleep)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert not await search.get_hostnames()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (FetcherResponse('', 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse('', 503, {}), 'failed', 'http-503'),
        (FetcherResponse({}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_initial_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse,
    status: str,
    reason: str,
) -> None:
    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)
    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    session_exited = False

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield object()
        finally:
            session_exited = True

    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)
    with pytest.raises(asyncio.CancelledError):
        await subdomainfinderc99.SearchSubdomainfinderc99('example.test').process()
    assert session_exited is True


pytestmark = pytest.mark.provider_contract('subdomainfinderc99')
