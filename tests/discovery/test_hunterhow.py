import asyncio
import base64
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import searchhunterhow
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('hunterhow')
@pytest.mark.asyncio
async def test_process_paginates_to_limit_and_keeps_scoped_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))
    session = object()
    session_exited = False
    session_options: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    delays: list[float] = []
    responses = [
        FetcherResponse(
            body={
                'code': 200,
                'data': {
                    'total': 3,
                    'list': [{'domain': 'API.Example.COM.'}, {'domain': 'outside.test'}],
                },
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'code': 200, 'data': {'total': 3, 'list': [{'domain': 'www.example.com'}]}},
            status=200,
            headers={},
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

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(searchhunterhow.asyncio, 'sleep', fake_sleep)
    search = searchhunterhow.SearchHunterHow('example.com', limit=3)

    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert session_options == [{'headers': {'User-Agent': searchhunterhow.Core.get_user_agent()}, 'proxy': True}]
    assert [call['params']['page'] for call in calls] == [1, 2]
    assert all(call['params']['page_size'] == 10 for call in calls)
    assert all(call['params']['api-key'] == 'test-key' for call in calls)
    assert all(base64.urlsafe_b64decode(call['params']['query']).decode() == 'domain.suffix="example.com"' for call in calls)
    assert all(call['session'] is session for call in calls)
    assert all(call['url'] == 'https://api.hunter.how/search' for call in calls)
    assert all(call['include_metadata'] is True for call in calls)
    assert delays == [2.0]
    assert report is None
    assert session_exited is True


@pytest.mark.asyncio
async def test_unlimited_search_has_no_local_history_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return FetcherResponse({'code': 200, 'data': {'total': 0, 'list': []}}, 200, {})

    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'fetch', fake_fetch)

    report = await searchhunterhow.SearchHunterHow('example.com', limit=None).process()

    assert report is None
    assert calls[0]['params']['start_time'] == '1970-01-01'


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_empty_key_fails_before_transport(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: key))

    with pytest.raises(MissingKey):
        searchhunterhow.SearchHunterHow('example.com', limit=10)


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 403, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse({'code': 40001}, 200, {}), 'failed', 'access-denied'),
        (FetcherResponse({'code': 200, 'data': {'total': 'three', 'list': {}}}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failed_response_is_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'fetch', fake_fetch)
    search = searchhunterhow.SearchHunterHow('example.com', limit=10)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert report.status == execution_status
    assert report.stop_reason == stop_reason


def test_limit_must_be_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))

    with pytest.raises(ValueError, match='positive integer'):
        searchhunterhow.SearchHunterHow('example.com', limit=0)


@pytest.mark.asyncio
async def test_early_malformed_rows_and_later_valid_evidence_are_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse({'code': 200, 'data': {'total': 2, 'list': [7]}}, 200, {}),
        FetcherResponse({'code': 200, 'data': {'total': 2, 'list': [{'domain': 'api.example.com'}]}}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(searchhunterhow.asyncio, 'sleep', fake_sleep)
    search = searchhunterhow.SearchHunterHow('example.com', limit=2)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(searchhunterhow.Core, 'hunterhow_key', staticmethod(lambda: 'test-key'))
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

    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchhunterhow.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await searchhunterhow.SearchHunterHow('example.com', limit=10).process()
    assert session_exited is True
