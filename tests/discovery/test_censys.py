import asyncio
import sys
import types
from pathlib import Path

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
async def test_search_calls_platform_api_directly_and_follows_page_tokens(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', 'org-id'))
    calls: list[dict[str, object]] = []
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

    async def fake_post_fetch(url: str, **kwargs):
        calls.append({'url': url, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(censysearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = censysearch.SearchCensys('example.com', limit=250)

    await search.process(proxy=True)

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
    assert await search.get_hostnames() == {'a.example.com', 'b.example.com'}
    assert await search.get_emails() == {'admin@example.com', 'ops@example.com'}
    assert search.execution_status == 'completed'


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

    await search.process()

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

    await search.process()

    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


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

    await search.process()

    assert await search.get_hostnames() == {'a.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


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

    await search.process()

    assert search.execution_status == expected_status
    assert search.stop_reason == expected_reason


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

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


def test_deprecated_censys_sdk_is_not_a_runtime_dependency() -> None:
    assert '"censys==' not in Path('pyproject.toml').read_text()
