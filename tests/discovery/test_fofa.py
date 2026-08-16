import asyncio
import base64
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import fofa
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('fofa')
@pytest.mark.asyncio
async def test_process_uses_cursor_api_to_limit_and_retains_scoped_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    session = object()
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {'error': False, 'results': [['https://API.Example.COM:443', '192.0.2.10']], 'next': 'cursor-2'},
            200,
            {},
        ),
        FetcherResponse(
            {
                'error': False,
                'results': [['https://outside.test', 'not-an-ip'], ['mail.example.com', '2001:db8::10']],
            },
            200,
            {},
        ),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        assert kwargs['proxy'] is True
        yield session

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(fofa.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    search = fofa.SearchFofa('example.com', limit=3)

    await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'mail.example.com'}
    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'
    assert [call['params']['size'] for call in calls] == [3, 2]
    assert [call['params'].get('next') for call in calls] == [None, 'cursor-2']
    assert all(call['url'] == 'https://fofa.info/api/v1/search/next' for call in calls)
    assert all(call['session'] is session for call in calls)
    assert base64.b64decode(calls[0]['params']['qbase64']).decode() == 'domain="example.com"'


@pytest.mark.parametrize(
    'credentials',
    [(None, 'operator@example.com'), ('', 'operator@example.com'), ('test-key', '   ')],
)
def test_missing_or_blank_credentials_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    credentials: tuple[str | None, str],
) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: credentials)
    with pytest.raises(MissingKey):
        fofa.SearchFofa('example.com', 10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_positive(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    with pytest.raises(ValueError, match='positive integer'):
        fofa.SearchFofa('example.com', limit)


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'error': True, 'errmsg': 'Invalid credentials'}, 200, {}), 'failed', 'access-denied'),
        (FetcherResponse({'error': True, 'errmsg': 'Quota limit reached'}, 200, {}), 'failed', 'quota-exhausted'),
        (FetcherResponse({'error': False, 'results': {}}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(fofa.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    search = fofa.SearchFofa('example.com', 10)
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_repeated_cursor_stops_without_a_third_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    responses = [
        FetcherResponse({'error': False, 'results': [['api.example.com', '192.0.2.1']], 'next': 'same'}, 200, {}),
        FetcherResponse({'error': False, 'results': [['mail.example.com', '192.0.2.2']], 'next': 'same'}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(fofa.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    search = fofa.SearchFofa('example.com', 10)
    await search.process()

    assert search.execution_status == 'partial'
    assert search.stop_reason == 'repeated-cursor'
    assert responses == []


@pytest.mark.asyncio
async def test_malformed_url_does_not_discard_later_valid_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    response = FetcherResponse(
        {
            'error': False,
            'results': [
                ['https://[invalid', 'not-an-ip'],
                ['https://api.example.com', '192.0.2.10'],
            ],
        },
        200,
        {},
    )

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return response

    monkeypatch.setattr(fofa.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    search = fofa.SearchFofa('example.com', 2)
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(fofa.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    with pytest.raises(asyncio.CancelledError):
        await fofa.SearchFofa('example.com', 10).process()
