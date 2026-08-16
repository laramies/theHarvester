import asyncio
import contextlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from theHarvester.discovery import urlscan
from theHarvester.lib.core import FetcherResponse


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> object:
    session = object()

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield session

    monkeypatch.setattr(urlscan.AsyncFetcher, 'open_session', fake_open_session)
    return session


@pytest.mark.asyncio
async def test_process_collects_sequential_pages_and_preserves_all_routes(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: object,
) -> None:
    responses = [
        FetcherResponse(
            body={
                'results': [
                    {
                        'page': {
                            'domain': 'first.example.com',
                            'ip': '192.0.2.10',
                            'url': 'https://first.example.com/path',
                            'asn': 'AS64496',
                            'asnname': 'Example Transit One',
                        },
                        'sort': [200, 'first'],
                    }
                ]
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={
                'results': [
                    {
                        'page': {
                            'domain': 'second.example.com',
                            'ip': '2001:db8::10',
                            'url': 'https://second.example.com/',
                            'asn': 'AS64497',
                            'asnname': 'Example Transit Two',
                        },
                        'sort': [100, 'second'],
                    }
                ]
            },
            status=200,
            headers={},
        ),
        FetcherResponse(body={'results': []}, status=200, headers={}),
    ]
    calls: list[dict[str, Any]] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process(proxy=True)

    assert await search.get_hostnames() == {'first.example.com', 'second.example.com'}
    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}
    assert await search.get_urls() == {
        'https://first.example.com/path',
        'https://second.example.com/',
    }
    assert await search.get_asns() == {'AS64496', 'AS64497'}
    assert {
        (
            observation.asn,
            observation.organization_label,
            observation.subject_kind,
            observation.subject_value,
        )
        for observation in await search.get_asn_attributions()
    } == {
        ('AS64496', 'Example Transit One', 'hostname', 'first.example.com'),
        ('AS64496', 'Example Transit One', 'ip', '192.0.2.10'),
        ('AS64497', 'Example Transit Two', 'hostname', 'second.example.com'),
        ('AS64497', 'Example Transit Two', 'ip', '2001:db8::10'),
    }
    assert [call['params'] for call in calls] == [
        {'q': 'domain:example.com'},
        {'q': 'domain:example.com', 'search_after': '200,first'},
        {'q': 'domain:example.com', 'search_after': '100,second'},
    ]
    assert all(call['url'] == 'https://urlscan.io/api/v1/search/' for call in calls)
    assert all(call['session'] is provider_session for call in calls)
    assert all(call['json'] is True for call in calls)
    assert all(call['include_metadata'] is True for call in calls)
    assert all('request_timeout' not in call for call in calls)
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_repeated_asn_relationship_is_retained_once_per_source_run(monkeypatch: pytest.MonkeyPatch) -> None:
    moments = iter((datetime(2026, 8, 12, tzinfo=UTC), datetime(2026, 8, 12, tzinfo=UTC) + timedelta(seconds=1)))

    class TickingDateTime:
        @classmethod
        def now(cls, timezone: object) -> datetime:
            assert timezone is UTC
            return next(moments)

    page = {
        'domain': 'api.example.com',
        'ip': '192.0.2.10',
        'url': 'https://api.example.com/',
        'asn': 'AS64496',
        'asnname': 'Example Transit',
    }
    responses = [
        FetcherResponse(body={'results': [{'page': page, 'sort': [2, 'first']}]}, status=200, headers={}),
        FetcherResponse(body={'results': [{'page': page, 'sort': [1, 'second']}]}, status=200, headers={}),
        FetcherResponse(body={'results': []}, status=200, headers={}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(urlscan, 'datetime', TickingDateTime)
    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert len(await search.get_asn_attributions()) == 2


@pytest.mark.asyncio
async def test_valid_empty_response_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={'results': []}, status=200, headers={})

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert await search.get_urls() == set()
    assert await search.get_asns() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_missing_optional_fields_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(
            body={'results': [{'sort': [2, 'missing-page']}, {'page': {}, 'sort': [1, 'empty-page']}]},
            status=200,
            headers={},
        ),
        FetcherResponse(body={'results': []}, status=200, headers={}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_malformed_nested_fields_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(
            body={
                'results': [
                    {'page': {'domain': 'valid.example.com'}, 'sort': [2, 'valid']},
                    {'page': {'domain': 7, 'ip': None, 'url': [], 'asn': {}}, 'sort': [1, 'malformed']},
                ]
            },
            status=200,
            headers={},
        ),
        FetcherResponse(body={'results': []}, status=200, headers={}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert await search.get_hostnames() == {'valid.example.com'}
    assert await search.get_ips() == set()
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_results_are_typed_and_scoped_before_insertion(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(
            body={
                'results': [
                    {
                        'page': {
                            'domain': 'API.Example.COM.',
                            'ip': '2001:0db8::10',
                            'url': 'https://portal.example.com/path',
                            'asn': 'as64496',
                        },
                        'sort': [2, 'valid'],
                    },
                    {
                        'page': {
                            'domain': 'notexample.com',
                            'ip': '198.51.100.20',
                            'url': 'https://outside.test/?q=example.com',
                            'asn': 'AS64497',
                        },
                        'sort': [1, 'rejected'],
                    },
                ]
            },
            status=200,
            headers={},
        ),
        FetcherResponse(body={'results': []}, status=200, headers={}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'2001:db8::10'}
    assert await search.get_urls() == {'https://portal.example.com/path'}
    assert await search.get_asns() == {'AS64496'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body=[], status=200, headers={}), 'failed', 'invalid-response'),
        (FetcherResponse(body={'results': {}}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failed_first_page_is_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.parametrize(
    ('second_response', 'stop_reason'),
    [
        (None, 'transport-error'),
        (FetcherResponse(body={}, status=403, headers={}), 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'http-503'),
        (FetcherResponse(body={'results': {}}, status=200, headers={}), 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_later_failure_preserves_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    second_response: FetcherResponse | None,
    stop_reason: str,
) -> None:
    responses = [
        FetcherResponse(
            body={'results': [{'page': {'domain': 'first.example.com'}, 'sort': [1, 'first']}]},
            status=200,
            headers={},
        ),
        second_response,
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_fetch_exception_is_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise OSError('private transport details')

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_missing_cursor_stops_after_first_page(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return FetcherResponse(
            body={'results': [{'page': {'domain': 'first.example.com'}}]},
            status=200,
            headers={},
        )

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert calls == 1
    assert await search.get_hostnames() == {'first.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-cursor'


@pytest.mark.asyncio
async def test_repeated_cursor_stops_without_a_third_request(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(
            body={'results': [{'page': {'domain': 'first.example.com'}, 'sort': [1, 'same']}]},
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'results': [{'page': {'domain': 'second.example.com'}, 'sort': [1, 'same']}]},
            status=200,
            headers={},
        ),
    ]
    calls = 0

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert calls == 2
    assert await search.get_hostnames() == {'first.example.com', 'second.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'repeated-cursor'


@pytest.mark.asyncio
async def test_pagination_continues_beyond_the_removed_local_page_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        if calls == 1002:
            return FetcherResponse(body={'results': []}, status=200, headers={})
        return FetcherResponse(
            body={
                'results': [
                    {
                        'page': {'domain': f'page-{calls}.example.com'},
                        'sort': [calls, f'cursor-{calls}'],
                    }
                ]
            },
            status=200,
            headers={},
        )

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com')

    await search.process()

    assert calls == 1002
    assert await search.get_hostnames() == {f'page-{page}.example.com' for page in range(1, 1002)}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError):
        await urlscan.SearchUrlscan('example.com').process()


pytestmark = pytest.mark.provider_contract('urlscan')
