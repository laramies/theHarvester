from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import haveibeenransom
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.provider_contract('haveibeenransom')

BASE_URL = 'https://haveibeenransom.com/api/metadata/domain/example.com'


class ProviderSession:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}
        self.lifecycle: list[str] = []


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> ProviderSession:
    session = ProviderSession()

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        session.kwargs = kwargs
        session.lifecycle.append('open')
        try:
            yield session
        finally:
            session.lifecycle.append('close')

    monkeypatch.setattr(haveibeenransom.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(haveibeenransom.Core, 'haveibeenransom_key', staticmethod(lambda: 'test-key'))
    return session


def respond(monkeypatch: pytest.MonkeyPatch, *responses: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    pending = iter(responses)

    async def fake_fetch_json(url: str, **kwargs: Any) -> Any:
        calls.append({'url': url, **kwargs})
        response = next(pending)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(haveibeenransom.AsyncFetcher, 'fetch_json', fake_fetch_json)
    return calls


def leak(leak_id: str, title: str, group: str, *, website: str = '', leak_type: str = 'ransomware_leak') -> dict[str, Any]:
    return {
        'id_source': leak_id,
        'post_title': title,
        'group_name': group,
        'website': website,
        'discovered': '2024-01-01',
        'leak_type': leak_type,
    }


def page(entries: list[Any], *, has_next: bool = False, number: int = 1) -> FetcherResponse:
    return FetcherResponse(
        {'sources': entries, 'count': len(entries), 'page': number, 'page_size': 20, 'has_next': has_next},
        200,
        {},
    )


@pytest.mark.asyncio
async def test_pages_are_followed_and_leaks_deduplicated_across_them(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    calls = respond(
        monkeypatch,
        page(
            [
                leak('101', 'Example Corp', 'akira', website='example.com'),
                leak('db-7', 'example.com customers', 'DBs Backup', leak_type='traditional_breach'),
            ],
            has_next=True,
        ),
        # Leaks without metadata are dropped by the provider, so a page can be empty and still have a next page.
        page([], has_next=True, number=2),
        # A leak indexed during the conversation is repeated at the top of a later page.
        page([leak('101', 'Example Corp (renamed)', 'akira'), leak('102', 'Example Labs', 'play')], number=3),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('Example.COM', limit=None)

    report = await search.process(proxy=True)

    assert report is None
    assert await search.get_breach_names() == {
        'Example Corp (akira)',
        'example.com customers (DBs Backup)',
        'Example Labs (play)',
    }
    assert [call['url'] for call in calls] == [BASE_URL, f'{BASE_URL}/2', f'{BASE_URL}/3']
    assert all(call['session'] is provider_session for call in calls)
    assert provider_session.kwargs == {
        'headers': {'Accept': 'application/json', 'Authorization': 'Bearer test-key'},
        'proxy': True,
        'request_timeout': 60,
    }
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_names_are_normalized_and_fall_back_to_the_website(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        page(
            [
                leak('1', '  Example\n Corp ', '𝐃𝐁𝐬  𝐁𝐚𝐜𝐤𝐮𝐩'),
                leak('2', '', 'lockbit3', website='shop.example.com'),
                leak('3', 'Example dump', ''),
                {'id_source': '4', 'post_title': 'Example Holdings'},
            ]
        ),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {
        'Example Corp (DBs Backup)',
        'shop.example.com (lockbit3)',
        'Example dump',
        'Example Holdings',
    }


@pytest.mark.asyncio
async def test_documented_response_shape_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        FetcherResponse({'success': True, 'results': [leak('1', 'Example Corp', 'akira')], 'pagination': {'has_next': True}}, 200, {}),
        FetcherResponse({'success': True, 'results': [], 'pagination': {'has_next': False}}, 200, {}),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {'Example Corp (akira)'}


@pytest.mark.asyncio
async def test_empty_result_completes_normally(monkeypatch: pytest.MonkeyPatch, provider_session: ProviderSession) -> None:
    calls = respond(monkeypatch, FetcherResponse({'sources': [], 'total_sources': 0, 'has_next': False}, 200, {}))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == set()
    assert len(calls) == 1
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(haveibeenransom.Core, 'haveibeenransom_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        haveibeenransom.SearchHaveIBeenRansom('example.com')


@pytest.mark.parametrize('target', ['', '*.example.com', 'exam?le.com', 'example', '192.0.2.1', 'example.com/path'])
@pytest.mark.asyncio
async def test_targets_that_are_not_domains_are_rejected_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    target: str,
) -> None:
    calls = respond(monkeypatch)
    search = haveibeenransom.SearchHaveIBeenRansom(target)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-target')
    assert calls == []
    assert provider_session.lifecycle == []


@pytest.mark.parametrize(
    ('status', 'report'),
    [
        (401, SourceExecutionReport('failed', 'access-denied')),
        (403, SourceExecutionReport('failed', 'access-denied')),
        (404, SourceExecutionReport('failed', 'http-404')),
        (429, SourceExecutionReport('rate-limited', 'http-429')),
        (500, SourceExecutionReport('failed', 'http-500')),
        (503, SourceExecutionReport('failed', 'http-503')),
    ],
)
@pytest.mark.asyncio
async def test_http_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    status: int,
    report: SourceExecutionReport,
) -> None:
    respond(monkeypatch, FetcherResponse(None, status, {}))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == report
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_a_failure_on_a_later_page_keeps_earlier_results(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        page([leak('1', 'Example Corp', 'akira')], has_next=True),
        FetcherResponse(None, 429, {}),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('rate-limited', 'http-429')
    assert await search.get_breach_names() == {'Example Corp (akira)'}


@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
@pytest.mark.asyncio
async def test_bounded_fetch_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    reason: str,
) -> None:
    respond(monkeypatch, ResponseStreamError(reason))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('failed', reason)
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.parametrize('failure_point', ['open', 'close'])
@pytest.mark.asyncio
async def test_session_lifecycle_failures_are_transport_errors(monkeypatch: pytest.MonkeyPatch, failure_point: str) -> None:
    @contextlib.asynccontextmanager
    async def failing_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    monkeypatch.setattr(haveibeenransom.AsyncFetcher, 'open_session', failing_open_session)
    respond(monkeypatch, page([]))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_cancellation_propagates_and_closes_the_session(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    respond(monkeypatch, page([leak('1', 'Example Corp', 'akira')], has_next=True), haveibeenransom.asyncio.CancelledError())
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    with pytest.raises(haveibeenransom.asyncio.CancelledError):
        await search.process()
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.parametrize(
    'body',
    [
        None,
        [],
        {},
        {'sources': 'many', 'has_next': False},
        {'sources': []},
        {'sources': [], 'has_next': 'false'},
        {'error': 'Server error during metadata search'},
    ],
)
@pytest.mark.asyncio
async def test_malformed_payloads_are_reported(monkeypatch: pytest.MonkeyPatch, body: Any) -> None:
    respond(monkeypatch, FetcherResponse(body, 200, {}))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == set()


@pytest.mark.asyncio
async def test_malformed_entries_keep_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example Corp', 'akira'), 'bad', {'id_source': '2', 'post_title': 7}]))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == {'Example Corp (akira)'}


@pytest.mark.asyncio
async def test_result_limit_stops_before_the_next_page(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = respond(
        monkeypatch,
        page([leak('1', 'Example A', 'akira'), leak('2', 'Example B', 'play')], has_next=True),
        page([leak('3', 'Example C', 'akira')], number=2),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('example.com', limit=2)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_breach_names() == {'Example A (akira)', 'Example B (play)'}
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_result_limit_inside_a_page_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example A', 'akira'), leak('2', 'Example A', 'akira'), leak('3', 'Example B', 'play')]))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com', limit=1)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_breach_names() == {'Example A (akira)'}


@pytest.mark.asyncio
async def test_reaching_the_limit_on_the_last_page_completes_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example A', 'akira'), leak('2', 'Example B', 'play')]))
    search = haveibeenransom.SearchHaveIBeenRansom('example.com', limit=2)

    assert await search.process() is None
    assert await search.get_breach_names() == {'Example A (akira)', 'Example B (play)'}


@pytest.mark.asyncio
async def test_page_guard_reports_incomplete_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(haveibeenransom.SearchHaveIBeenRansom, 'MAX_PAGES', 2)
    calls = respond(
        monkeypatch,
        page([leak('1', 'Example A', 'akira')], has_next=True),
        page([leak('2', 'Example B', 'play')], has_next=True, number=2),
    )
    search = haveibeenransom.SearchHaveIBeenRansom('example.com')

    assert await search.process() == SourceExecutionReport('partial', 'provider-limit')
    assert await search.get_breach_names() == {'Example A (akira)', 'Example B (play)'}
    assert len(calls) == 2
