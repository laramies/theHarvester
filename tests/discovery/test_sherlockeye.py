import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import sherlockeye
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'open_session', fake_open_session)


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_raises(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: key)

    with pytest.raises(MissingKey):
        sherlockeye.SearchSherlockeye('example.com')


@pytest.mark.asyncio
async def test_process_uses_one_shared_provider_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    session = object()
    exited = False
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal exited
        assert kwargs == {
            'headers': {
                'User-Agent': sherlockeye.Core.get_user_agent(),
                'Authorization': 'Bearer dummy-key',
                'Content-Type': 'application/json',
            },
            'proxy': True,
            'request_timeout': 90,
        }
        try:
            yield session
        finally:
            exited = True

    async def fake_post_fetch(*args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append({'url': args[0], **kwargs})
        return FetcherResponse({'success': True, 'data': {'results': []}}, 200, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = sherlockeye.SearchSherlockeye('example.com')

    report = await search.process(proxy=True)

    assert calls == [
        {
            'url': search.SYNC_SEARCH_URL,
            'session': session,
            'json': True,
            'include_metadata': True,
            'json_body': {
                'type': 'domain',
                'value': 'example.com',
                'timeoutSeconds': 60,
            },
        }
    ]
    assert exited is True
    assert report is None


@pytest.mark.asyncio
async def test_process_extracts_domain_intelligence(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    api_payload = {
        'success': True,
        'data': {
            'searchId': 'search-1',
            'type': 'domain',
            'value': 'example.com',
            'timeoutSeconds': 60,
            'status': 'complete',
            'progress': 100,
            'results': [
                {
                    'id': 'result-1',
                    'source': 'provider-a',
                    'attributes': {
                        'domain': 'sub.example.com',
                        'email': 'user@example.com',
                        'ip': '203.0.113.10',
                        'link': 'https://www.example.com/path',
                    },
                },
                {
                    'id': 'result-2',
                    'source': 'provider-b',
                    'attributes': {
                        'email': 'other@not-example.org',
                        'link': 'https://api.example.com/docs',
                    },
                },
                {'attributes': {'email': 'user@notexample.com'}},
                {'attributes': {'email': 'user@example.com.evil'}},
            ],
        },
        'balance': {'credits': 10},
    }

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(api_payload, 200, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()

    assert await search.get_hostnames() == {'sub.example.com', 'www.example.com', 'api.example.com'}
    assert await search.get_emails() == {'user@example.com'}
    assert await search.get_ips() == {'203.0.113.10'}
    assert report is None


@pytest.mark.asyncio
async def test_process_handles_api_error(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'secret': 'provider-secret-payload'}, 401, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_emails() == set()
    assert await search.get_ips() == set()
    assert 'provider-secret-payload' not in caplog.text
    assert '401' in caplog.text
    assert report.status == 'failed'
    assert report.stop_reason == 'access-denied'


@pytest.mark.asyncio
async def test_process_does_not_log_provider_error_message(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'success': False, 'message': 'provider-secret-payload'}, 200, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'API error' in caplog.text
    assert report.status == 'failed'
    assert report.stop_reason == 'provider-error'


@pytest.mark.parametrize(
    ('status', 'execution_status', 'stop_reason'),
    [(429, 'rate-limited', 'http-429'), (503, 'failed', 'http-503')],
)
@pytest.mark.asyncio
async def test_http_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({}, status, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()

    assert report.status == execution_status
    assert report.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_malformed_response_is_structured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse([], 200, {})

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


def test_malformed_link_does_not_discard_later_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    search = sherlockeye.SearchSherlockeye('example.com')

    report = search._extract_response(
        {
            'success': True,
            'data': {
                'results': [
                    {'attributes': {'link': 'https://[invalid'}},
                    {'attributes': {'link': 'https://api.example.com/path'}},
                ]
            },
        }
    )

    assert search.totalhosts == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_transport_failure_and_cancellation_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    session_exit_count = 0

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exit_count
        try:
            yield object()
        finally:
            session_exit_count += 1

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'open_session', fake_open_session)

    async def failed_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise RuntimeError('provider-secret')

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', failed_post_fetch)
    search = sherlockeye.SearchSherlockeye('example.com')
    report = await search.process()
    assert report.status == 'failed'
    assert report.stop_reason == 'transport-error'
    assert session_exit_count == 1

    async def cancelled_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(sherlockeye.AsyncFetcher, 'post_fetch', cancelled_post_fetch)
    with pytest.raises(asyncio.CancelledError):
        await sherlockeye.SearchSherlockeye('example.com').process()
    assert session_exit_count == 2


pytestmark = pytest.mark.provider_contract('sherlockeye')
