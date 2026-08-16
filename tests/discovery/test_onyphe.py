import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import onyphe
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('onyphe')
@pytest.mark.asyncio
async def test_process_paginates_to_limit_and_preserves_all_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    session = object()
    session_exited = False
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {
                'text': 'Success',
                'total': 3,
                'max_page': 2,
                'results': [
                    {
                        'ip': '192.0.2.10',
                        'alternativeip': ['2001:0db8::10'],
                        'url': ['https://www.example.com/path'],
                        'asn': 'AS64496',
                        'organization': 'Example Physical Network',
                        'geolocus': {
                            'asn': 'AS64497',
                            'organization': 'Example Logical Network',
                            'domain': ['geo.example.com'],
                        },
                        'hostname': ['api.example.com'],
                    },
                    {'hostname': ['outside.test']},
                ],
            },
            200,
            {},
        ),
        FetcherResponse(
            {'text': 'Success', 'total': 3, 'max_page': 2, 'results': [{'subdomains': ['mail.example.com']}]},
            200,
            {},
        ),
    ]

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        assert kwargs['proxy'] is True
        assert kwargs['headers']['Authorization'] == 'bearer test-key'
        try:
            yield session
        finally:
            session_exited = True

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', limit=3)
    await search.process(proxy=True)

    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}
    assert await search.get_hostnames() == {'api.example.com', 'geo.example.com', 'mail.example.com', 'www.example.com'}
    assert await search.get_asns() == {'AS64496', 'AS64497'}
    assert {
        (item.asn, item.organization_label, item.subject_kind, item.subject_value) for item in await search.get_asn_attributions()
    } == {
        ('AS64496', 'Example Physical Network', 'ip', '192.0.2.10'),
        ('AS64497', 'Example Logical Network', 'ip', '192.0.2.10'),
    }
    assert [call['params']['page'] for call in calls] == [1, 2]
    assert [call['params']['size'] for call in calls] == [3, 3]
    assert all(call['session'] is session for call in calls)
    assert search.execution_status == 'completed'
    assert search.stop_reason is None
    assert session_exited is True


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: key)
    with pytest.raises(MissingKey):
        onyphe.SearchOnyphe('example.com', 10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_positive(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    with pytest.raises(ValueError, match='positive integer'):
        onyphe.SearchOnyphe('example.com', limit)


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'text': 'Denied'}, 200, {}), 'failed', 'provider-error'),
        (FetcherResponse({'text': 'Success', 'results': {}}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', 10)
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_later_page_failure_preserves_partial_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    responses = [
        FetcherResponse(
            {'text': 'Success', 'total': 2, 'max_page': 2, 'results': [{'ip': '192.0.2.10'}]},
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

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', 2)
    await search.process()

    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'http-429'


@pytest.mark.asyncio
async def test_operator_limit_is_not_reported_as_a_provider_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    response = FetcherResponse(
        {
            'text': 'Success',
            'total': 3,
            'max_page': 2,
            'results': [{'ip': '192.0.2.10'}, {'ip': '192.0.2.11'}],
        },
        200,
        {},
    )

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return response

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', 2)
    await search.process()

    assert await search.get_ips() == {'192.0.2.10', '192.0.2.11'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_search_api_reports_its_documented_total_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    calls: list[dict[str, Any]] = []
    response = FetcherResponse(
        {
            'text': 'Success',
            'total': 10_001,
            'max_page': 2,
            'results': [{'hostname': ['api.example.com']}, *({} for _ in range(9_999))],
        },
        200,
        {},
    )

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return response

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', 10_001)
    await search.process()

    assert [call['params']['page'] for call in calls] == [1]
    assert [call['params']['size'] for call in calls] == [10_000]
    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'provider-limit'


@pytest.mark.asyncio
async def test_malformed_items_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    response = FetcherResponse(
        {
            'text': 'Success',
            'results': [{'ip': '192.0.2.10', 'alternativeip': ['not-an-ip', None]}, 'malformed-record'],
        },
        200,
        {},
    )

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield object()

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return response

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    search = onyphe.SearchOnyphe('example.com', 10)
    await search.process()

    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    session_exited = False

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        nonlocal session_exited
        try:
            yield object()
        finally:
            session_exited = True

    monkeypatch.setattr(onyphe.AsyncFetcher, 'open_session', fake_open_session)
    cancellation = asyncio.CancelledError('operator-stop')

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise cancellation

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch', fake_fetch)
    with pytest.raises(asyncio.CancelledError) as caught:
        await onyphe.SearchOnyphe('example.com', 10).process()
    assert caught.value is cancellation
    assert session_exited is True
