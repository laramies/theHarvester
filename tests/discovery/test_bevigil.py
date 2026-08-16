import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import bevigil
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('bevigil')
@pytest.mark.asyncio
async def test_process_collects_scoped_hostnames_and_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: 'test-key'))
    session = object()
    session_exited = False
    open_calls: list[dict[str, Any]] = []
    calls: list[tuple[list[str], dict[str, Any]]] = []
    responses = [
        FetcherResponse(
            body={'subdomains': ['API.Example.COM.', 'outside.test']},
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'urls': ['https://portal.example.com/path', 'https://outside.test/example.com']},
            status=200,
            headers={},
        ),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        open_calls.append(kwargs)
        try:
            yield session
        finally:
            session_exited = True

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        calls.append((urls, kwargs))
        return [responses.pop(0)]

    monkeypatch.setattr(bevigil.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(bevigil.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bevigil.SearchBeVigil('example.com')

    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_urls() == {'https://portal.example.com/path'}
    assert [urls for urls, _kwargs in calls] == [
        ['https://osint.bevigil.com/api/example.com/subdomains/'],
        ['https://osint.bevigil.com/api/example.com/urls/'],
    ]
    assert all(kwargs['headers'] == {'X-Access-Token': 'test-key'} for _urls, kwargs in calls)
    assert all(kwargs['proxy'] is True for _urls, kwargs in calls)
    assert all(kwargs['json'] is True for _urls, kwargs in calls)
    assert all(kwargs['include_metadata'] is True for _urls, kwargs in calls)
    assert all(kwargs['session'] is session for _urls, kwargs in calls)
    assert open_calls == [
        {
            'headers': {'X-Access-Token': 'test-key'},
            'proxy': True,
            'request_timeout': 60,
        }
    ]
    assert session_exited is True
    assert report is None


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_empty_key_fails_before_transport(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: key))

    with pytest.raises(MissingKey):
        bevigil.SearchBeVigil('example.com')


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body={'subdomains': {}}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failed_first_response_is_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(bevigil.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bevigil.SearchBeVigil('example.com')

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_urls() == set()
    assert report.status == execution_status
    assert report.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_later_malformed_response_preserves_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(body={'subdomains': ['api.example.com']}, status=200, headers={}),
        FetcherResponse(body={'urls': {}}, status=200, headers={}),
    ]

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(bevigil.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bevigil.SearchBeVigil('example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_urls() == set()
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: 'test-key'))
    session_exited = False

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield object()
        finally:
            session_exited = True

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(bevigil.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(bevigil.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await bevigil.SearchBeVigil('example.com').process()
    assert session_exited is True


@pytest.mark.asyncio
async def test_early_malformed_rows_and_later_valid_evidence_are_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bevigil.Core, 'bevigil_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(body={'subdomains': [7]}, status=200, headers={}),
        FetcherResponse(body={'urls': ['https://portal.example.com/path']}, status=200, headers={}),
    ]

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(bevigil.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bevigil.SearchBeVigil('example.com')

    report = await search.process()

    assert await search.get_urls() == {'https://portal.example.com/path'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'
