from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import virustotal
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.mark.provider_contract('virustotal')
@pytest.mark.asyncio
async def test_process_paginates_without_fixed_sleeps_and_keeps_scoped_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: 'test-key'))
    session = object()
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {
                'data': [
                    {
                        'id': 'API.Example.COM.',
                        'attributes': {
                            'last_dns_records': [{'value': 'dns.example.com'}],
                            'last_https_certificate': {
                                'extensions': {'subject_alternative_name': ['tls.example.com', 'outside.test']}
                            },
                        },
                    }
                ],
                'meta': {'cursor': 'next-page'},
            },
            200,
            {},
        ),
        FetcherResponse(
            {'data': [{'id': 'mail.example.com', 'attributes': {'last_dns_records': []}}], 'meta': {}},
            200,
            {},
        ),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        assert kwargs == {
            'headers': {
                'Accept': 'application/json',
                'x-apikey': 'test-key',
            },
            'proxy': True,
        }
        yield session

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(virustotal.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', fake_fetch)
    search = virustotal.SearchVirustotal('example.com', limit=10)
    await search.process(proxy=True)

    assert await search.get_hostnames() == {
        'api.example.com',
        'dns.example.com',
        'mail.example.com',
        'tls.example.com',
    }
    assert search.execution_status == 'completed'
    assert search.stop_reason is None
    assert [call['params'] for call in calls] == [{'limit': 10}, {'limit': 9, 'cursor': 'next-page'}]
    assert all(call['session'] is session for call in calls)


@pytest.mark.asyncio
async def test_parse_hostnames_preserves_www_evidence() -> None:
    data = [
        {
            'id': 'www.example.com',
            'attributes': {
                'last_dns_records': [{'value': 'www.api.example.com'}],
                'last_https_certificate': {'extensions': {'subject_alternative_name': ['www.mail.example.com']}},
            },
        }
    ]

    hostnames, malformed = virustotal.SearchVirustotal.parse_hostnames(data, 'example.com')
    assert hostnames == {'www.api.example.com', 'www.example.com', 'www.mail.example.com'}
    assert malformed is False


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        virustotal.SearchVirustotal('example.com', limit=10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: 'test-key'))
    with pytest.raises(ValueError, match='positive integer'):
        virustotal.SearchVirustotal('example.com', limit=limit)


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
async def test_provider_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: 'test-key'))

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(virustotal.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', fake_fetch)
    search = virustotal.SearchVirustotal('example.com', limit=10)
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_later_rate_limit_preserves_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(
            {'data': [{'id': 'api.example.com', 'attributes': {}}], 'meta': {'cursor': 'next'}},
            200,
            {},
        ),
        FetcherResponse({}, 429, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(virustotal.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', fake_fetch)
    search = virustotal.SearchVirustotal('example.com', limit=10)
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'http-429'


@pytest.mark.asyncio
async def test_repeated_cursor_stops_without_spending_more_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse({'data': [{'id': 'outside.test', 'attributes': {}}], 'meta': {'cursor': 'same'}}, 200, {}),
        FetcherResponse({'data': [{'id': 'api.example.com', 'attributes': {}}], 'meta': {'cursor': 'same'}}, 200, {}),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(virustotal.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', fake_fetch)
    search = virustotal.SearchVirustotal('example.com', limit=10)

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'repeated-cursor'
    assert responses == []
