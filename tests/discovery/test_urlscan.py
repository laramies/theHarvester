from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import urlscan
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class ProviderSession:
    def __init__(self) -> None:
        self.exited = False


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> ProviderSession:
    session = ProviderSession()

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        try:
            yield session
        finally:
            session.exited = True

    monkeypatch.setattr(urlscan.AsyncFetcher, 'open_session', fake_open_session)
    return session


@pytest.mark.asyncio
async def test_process_collects_sequential_pages_and_preserves_all_routes(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
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
    ]
    calls: list[dict[str, Any]] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com', 2)

    report = await search.process(proxy=True)

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
        {'q': 'domain:example.com', 'size': 2},
        {'q': 'domain:example.com', 'size': 1, 'search_after': '200,first'},
    ]
    assert all(call['url'] == 'https://urlscan.io/api/v1/search/' for call in calls)
    assert all(call['session'] is provider_session for call in calls)
    assert all(call['json'] is True for call in calls)
    assert all(call['include_metadata'] is True for call in calls)
    assert all('request_timeout' not in call for call in calls)
    assert provider_session.exited is True
    assert report is None


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert len(await search.get_asn_attributions()) == 2
    assert report is None


@pytest.mark.asyncio
async def test_valid_empty_response_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={'results': []}, status=200, headers={})

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert await search.get_urls() == set()
    assert await search.get_asns() == set()
    assert report is None


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert report is None


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert await search.get_hostnames() == {'valid.example.com'}
    assert await search.get_ips() == set()
    assert report == SourceExecutionReport('failed', 'invalid-response')


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'2001:db8::10'}
    assert await search.get_urls() == {'https://portal.example.com/path'}
    assert await search.get_asns() == {'AS64496'}
    assert report is None


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport(execution_status, stop_reason)


@pytest.mark.parametrize(
    ('second_response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body={'results': {}}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_later_failure_preserves_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    second_response: FetcherResponse | None,
    execution_status: str,
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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert report == SourceExecutionReport(execution_status, stop_reason)


@pytest.mark.asyncio
async def test_fetch_exception_is_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise OSError('private transport details')

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('failed', 'transport-error')


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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert calls == 1
    assert await search.get_hostnames() == {'first.example.com'}
    assert report == SourceExecutionReport('failed', 'invalid-cursor')


@pytest.mark.parametrize(
    ('domains', 'expected_status', 'expected_hostnames'),
    [
        (('first.example.com', 'second.example.com'), 'partial', {'first.example.com', 'second.example.com'}),
        (('outside.test', 'other.test'), 'failed', set()),
    ],
)
@pytest.mark.asyncio
async def test_repeated_cursor_status_reflects_retained_evidence(
    monkeypatch: pytest.MonkeyPatch,
    domains: tuple[str, str],
    expected_status: str,
    expected_hostnames: set[str],
) -> None:
    responses = [
        FetcherResponse(
            body={'results': [{'page': {'domain': domains[0]}, 'sort': [1, 'same']}]},
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'results': [{'page': {'domain': domains[1]}, 'sort': [1, 'same']}]},
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
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert calls == 2
    assert await search.get_hostnames() == expected_hostnames
    assert report == SourceExecutionReport(expected_status, 'repeated-cursor')


@pytest.mark.asyncio
async def test_pagination_continues_beyond_the_removed_local_page_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    first_page = [
        {'page': {'domain': f'page-{index}.example.com'}, 'sort': [10_001 - index, f'cursor-{index}']}
        for index in range(1, 10_001)
    ]
    responses = [
        FetcherResponse(body={'results': first_page}, status=200, headers={}),
        FetcherResponse(
            body={
                'results': [
                    {
                        'page': {'domain': 'page-10001.example.com'},
                        'sort': [0, 'cursor-10001'],
                    }
                ]
            },
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['params'])
        return responses.pop(0)

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com', 10_001)

    report = await search.process()

    assert calls == [
        {'q': 'domain:example.com', 'size': 10_000},
        {'q': 'domain:example.com', 'size': 1, 'search_after': '1,cursor-10000'},
    ]
    assert await search.get_hostnames() == {f'page-{page}.example.com' for page in range(1, 10_002)}
    assert report is None


@pytest.mark.asyncio
async def test_operator_limit_sets_page_size_and_stops_without_an_extra_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    results = [
        {'page': {'domain': f'result-{index}.example.com'}, 'sort': [10 - index, f'cursor-{index}']} for index in range(10)
    ]

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['params'])
        return FetcherResponse(body={'results': results}, status=200, headers={})

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    search = urlscan.SearchUrlscan('example.com', 10)

    report = await search.process()

    assert calls == [{'q': 'domain:example.com', 'size': 10}]
    assert len(await search.get_hostnames()) == 10
    assert report is None


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(limit: Any) -> None:
    with pytest.raises(ValueError, match='positive integer'):
        urlscan.SearchUrlscan('example.com', limit)


@pytest.mark.asyncio
async def test_cancellation_propagates(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError):
        await urlscan.SearchUrlscan('example.com', 10).process()
    assert provider_session.exited is True


pytestmark = pytest.mark.provider_contract('urlscan')
