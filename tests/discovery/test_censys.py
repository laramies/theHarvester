from __future__ import annotations

import asyncio
import contextlib
import sys
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    aiohttp_socks_stub.ProxyConnector = _ProxyConnector
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import censysearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.mark.asyncio
async def test_missing_platform_token_raises(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: (None, 'org-id'))

    with pytest.raises(MissingKey, match='Personal Access Token'):
        censysearch.SearchCensys('example.com')


def test_legacy_search_api_credentials_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        censysearch.Core,
        'api_keys',
        staticmethod(lambda: {'censys': {'id': 'legacy-id', 'secret': 'legacy-secret'}}),
    )

    with pytest.raises(MissingKey, match='Personal Access Token'):
        censysearch.SearchCensys('example.com')


@pytest.mark.asyncio
async def test_search_calls_platform_api_directly_and_follows_page_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', 'org-id'))
    calls: list[dict[str, object]] = []
    session_options: list[dict[str, object]] = []
    session = object()
    responses = [
        FetcherResponse(
            {
                'result': {
                    'hits': [
                        {
                            'certificate_v1': {
                                'resource': {
                                    'names': ['a.example.com'],
                                    'parsed': {'subject': {'email_address': ['admin@example.com']}},
                                }
                            }
                        },
                        {'host_v1': {'resource': {'ip': '192.0.2.1'}}},
                    ],
                    'next_page_token': 'next-page',
                }
            },
            200,
            {},
        ),
        FetcherResponse(
            {
                'result': {
                    'hits': [
                        {
                            'certificate_v1': {
                                'resource': {
                                    'names': ['b.example.com'],
                                    'parsed': {'subject': {'email_address': 'ops@example.com'}},
                                }
                            }
                        }
                    ],
                    'next_page_token': '',
                }
            },
            200,
            {},
        ),
    ]

    async def fake_post_fetch(url: str, **kwargs: Any) -> FetcherResponse:
        calls.append({'url': url, **kwargs})
        return responses.pop(0)

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: object) -> AsyncIterator[object]:
        session_options.append(kwargs)
        yield session

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(censysearch.AsyncFetcher, 'open_session', fake_open_session)
    search = censysearch.SearchCensys('example.com', limit=250)

    report = await search.process(proxy=True)

    assert [call['url'] for call in calls] == [
        'https://api.platform.censys.io/v3/global/search/query',
        'https://api.platform.censys.io/v3/global/search/query',
    ]
    assert calls[0]['headers'] == {
        'Accept': 'application/json',
        'Authorization': 'Bearer platform-token',
    }
    assert calls[0]['params'] == {'organization_id': 'org-id'}
    assert calls[0]['json_body'] == {
        'query': 'cert.names: "example.com"',
        'fields': ['cert.names', 'cert.parsed.subject.email_address'],
        'page_size': 100,
    }
    assert calls[1]['json_body'] == {
        **calls[0]['json_body'],
        'page_token': 'next-page',
    }
    assert calls[0]['json'] is True
    assert calls[0]['proxy'] is True
    assert calls[0]['include_metadata'] is True
    assert session_options == [
        {
            'headers': {'Accept': 'application/json', 'Authorization': 'Bearer platform-token'},
            'proxy': True,
            'request_timeout': 720,
        }
    ]
    assert all(call['session'] is session for call in calls)
    assert await search.get_hostnames() == {'a.example.com', 'b.example.com'}
    assert await search.get_emails() == {'admin@example.com', 'ops@example.com'}
    assert report is None


@pytest.mark.asyncio
async def test_unlimited_search_follows_tokens_until_the_provider_terminates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))
    calls: list[dict[str, object]] = []
    responses = [
        FetcherResponse({'result': {'hits': [], 'next_page_token': 'next-page'}}, 200, {}),
        FetcherResponse({'result': {'hits': [], 'next_page_token': ''}}, 200, {}),
    ]

    async def fake_post_fetch(_url: str, **kwargs: object) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com', limit=None)

    assert await search.process() is None
    assert [call['json_body'] for call in calls] == [
        {
            'query': 'cert.names: "example.com"',
            'fields': ['cert.names', 'cert.parsed.subject.email_address'],
            'page_size': 100,
        },
        {
            'query': 'cert.names: "example.com"',
            'fields': ['cert.names', 'cert.parsed.subject.email_address'],
            'page_size': 100,
            'page_token': 'next-page',
        },
    ]


@pytest.mark.parametrize(
    ('hit', 'expected_status'),
    [
        ({'certificate_v1': {'resource': {'names': ['api.example.com']}}}, 'partial'),
        ({'host_v1': {'resource': {'ip': '192.0.2.1'}}}, 'failed'),
    ],
)
@pytest.mark.asyncio
async def test_repeated_cursor_status_reflects_retained_evidence(
    monkeypatch: pytest.MonkeyPatch,
    hit: dict[str, object],
    expected_status: str,
) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))
    responses = [
        FetcherResponse({'result': {'hits': [hit], 'next_page_token': 'same'}}, 200, {}),
        FetcherResponse({'result': {'hits': [], 'next_page_token': 'same'}}, 200, {}),
    ]

    async def fake_post_fetch(*_args: object, **_kwargs: object) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    report = await censysearch.SearchCensys('example.com', limit=None).process()

    assert report.status == expected_status
    assert report.stop_reason == 'repeated-cursor'


@pytest.mark.asyncio
async def test_session_setup_failure_reports_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', 'org-id'))

    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: object) -> AsyncIterator[object]:
        raise OSError('sensitive provider detail')
        yield object()

    monkeypatch.setattr(censysearch.AsyncFetcher, 'open_session', failed_open_session)
    search = censysearch.SearchCensys('example.com')

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_unexpected_adapter_failure_is_not_misclassified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', 'org-id'))
    search = censysearch.SearchCensys('example.com')

    async def failed_search() -> None:
        raise RuntimeError('adapter defect')

    monkeypatch.setattr(search, 'do_search', failed_search)

    with pytest.raises(RuntimeError, match='adapter defect'):
        await search.process()


@pytest.mark.asyncio
async def test_search_uses_free_wallet_and_respects_result_limit(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))
    calls: list[dict[str, object]] = []

    async def fake_post_fetch(_url: str, **kwargs):
        calls.append(kwargs)
        return FetcherResponse(
            {
                'result': {
                    'hits': [{'certificate_v1': {'resource': {'names': [f'{index}.example.com']}}} for index in range(1, 5)],
                    'next_page_token': 'ignored-after-limit',
                }
            },
            200,
            {},
        )

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com', limit=3)

    report = await search.process()

    assert report is None
    assert calls[0]['params'] == ''
    assert calls[0]['json_body']['page_size'] == 3
    assert await search.get_hostnames() == {'1.example.com', '2.example.com', '3.example.com'}
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_search_accepts_missing_terminal_page_token(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))

    async def fake_post_fetch(*_args, **_kwargs):
        return FetcherResponse({'result': {'hits': []}}, 200, {})

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com')

    report = await search.process()

    assert report is None


@pytest.mark.asyncio
async def test_malformed_limit_hit_is_partial_when_it_contains_evidence(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))

    async def fake_post_fetch(*_args, **_kwargs):
        return FetcherResponse(
            {
                'result': {
                    'hits': [{'certificate_v1': {'resource': {'names': ['a.example.com'], 'parsed': 'bad'}}}],
                    'next_page_token': 'unused',
                }
            },
            200,
            {},
        )

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com', limit=1)

    report = await search.process()

    assert await search.get_hostnames() == {'a.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.parametrize(
    ('response', 'expected_status', 'expected_reason'),
    [
        (FetcherResponse(None, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse(None, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({'result': {'hits': 'bad'}}, 200, {}), 'failed', 'invalid-response'),
        (None, 'failed', 'transport-error'),
    ],
)
@pytest.mark.asyncio
async def test_search_reports_provider_failures_truthfully(
    monkeypatch, response: FetcherResponse | None, expected_status: str, expected_reason: str
) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))

    async def fake_post_fetch(*_args, **_kwargs):
        return response

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com')

    report = await search.process()

    assert report.status == expected_status
    assert report.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_search_keeps_event_loop_responsive_and_propagates_cancellation(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))
    request_started = asyncio.Event()
    release_request = asyncio.Event()

    async def fake_post_fetch(*_args, **_kwargs):
        request_started.set()
        await release_request.wait()

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    task = asyncio.create_task(censysearch.SearchCensys('example.com').process())
    await request_started.wait()
    callback_ran = asyncio.Event()
    asyncio.get_running_loop().call_soon(callback_ran.set)

    await asyncio.wait_for(callback_ran.wait(), timeout=0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_search_classifies_transport_exceptions(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))

    async def fake_post_fetch(*_args, **_kwargs):
        raise OSError('offline')

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com')

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'transport-error'


def test_deprecated_censys_sdk_is_not_a_runtime_dependency() -> None:
    assert '"censys==' not in Path('pyproject.toml').read_text()


pytestmark = pytest.mark.provider_contract('censys')
