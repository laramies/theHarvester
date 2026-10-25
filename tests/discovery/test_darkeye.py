from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import darkeye
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.provider_contract('darkeye')

BASE_URL = 'https://haveibeenransom.com/api/metadata/domain/example.com'
BREACH_HOUSE_URL = 'https://breach.house/api/v1/search?q=example.com&limit=200'
HIBR = 'DarkEye | Have I Been Ransomed?'
BREACH_HOUSE = 'DarkEye | Breach House'


class ProviderSession:
    def __init__(self) -> None:
        self.kwargs: list[dict[str, Any]] = []
        self.lifecycle: list[str] = []


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> ProviderSession:
    session = ProviderSession()

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        session.kwargs.append(kwargs)
        session.lifecycle.append('open')
        try:
            yield session
        finally:
            session.lifecycle.append('close')

    monkeypatch.setattr(darkeye.AsyncFetcher, 'open_session', fake_open_session)
    use_keys(monkeypatch, 'hibr-key', None)
    return session


def use_keys(monkeypatch: pytest.MonkeyPatch, hibr_key: str | None, breach_house_key: str | None) -> None:
    monkeypatch.setattr(darkeye.Core, 'darkeye_keys', staticmethod(lambda: (hibr_key, breach_house_key)))


def respond(monkeypatch: pytest.MonkeyPatch, *responses: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    pending = iter(responses)

    async def fake_fetch_json(url: str, **kwargs: Any) -> Any:
        calls.append({'url': url, **kwargs})
        response = next(pending)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(darkeye.AsyncFetcher, 'fetch_json', fake_fetch_json)
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


def record(record_id: int, title: str, group: str, *, website: str = '', discovered: str = '2024-01-01 10:11:12') -> dict[str, Any]:
    return {'id': record_id, 'post_title': title, 'group_name': group, 'website': website, 'discovered': discovered}


def page(entries: list[Any], *, has_next: bool = False, number: int = 1) -> FetcherResponse:
    return FetcherResponse(
        {'sources': entries, 'count': len(entries), 'page': number, 'page_size': 20, 'has_next': has_next},
        200,
        {},
    )


def search_result(**sources: list[Any]) -> FetcherResponse:
    body = {name: {'results': [], 'total': 0} for name in ('ransomware', 'breaches', 'leads', 'stealers')}
    for name, results in sources.items():
        body[name] = {'results': results, 'total': len(results)}
    return FetcherResponse(body, 200, {})


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
    search = darkeye.SearchDarkEye('Example.COM', limit=None)

    report = await search.process(proxy=True)

    assert report is None
    assert await search.get_breach_names() == {
        f'Example Corp (akira) [{HIBR} | ransomware leak]',
        f'example.com customers (DBs Backup) [{HIBR} | data breach]',
        f'Example Labs (play) [{HIBR} | ransomware leak]',
    }
    assert [call['url'] for call in calls] == [BASE_URL, f'{BASE_URL}/2', f'{BASE_URL}/3']
    assert all(call['session'] is provider_session for call in calls)
    assert provider_session.kwargs == [
        {'headers': {'Accept': 'application/json', 'Authorization': 'Bearer hibr-key'}, 'proxy': True, 'request_timeout': 60}
    ]
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_names_are_normalized_and_fall_back_to_the_website(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        page(
            [
                leak('1', '  Example\n Corp ', '𝐃𝐁𝐬  𝐁𝐚𝐜𝐤𝐮𝐩'),
                leak('2', '', 'lockbit3', website='shop.example.com'),
                leak('3', 'Example dump', '', leak_type='traditional_breach'),
                {'id_source': '4', 'post_title': 'Example Holdings'},
            ]
        ),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {
        f'Example Corp (DBs Backup) [{HIBR} | ransomware leak]',
        f'shop.example.com (lockbit3) [{HIBR} | ransomware leak]',
        f'Example dump [{HIBR} | data breach]',
        f'Example Holdings [{HIBR} | data leak]',
    }


@pytest.mark.asyncio
async def test_documented_response_shape_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        FetcherResponse({'success': True, 'results': [leak('1', 'Example Corp', 'akira')], 'pagination': {'has_next': True}}, 200, {}),
        FetcherResponse({'success': True, 'results': [], 'pagination': {'has_next': False}}, 200, {}),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {f'Example Corp (akira) [{HIBR} | ransomware leak]'}


@pytest.mark.asyncio
async def test_empty_result_completes_normally(monkeypatch: pytest.MonkeyPatch, provider_session: ProviderSession) -> None:
    calls = respond(monkeypatch, FetcherResponse({'sources': [], 'total_sources': 0, 'has_next': False}, 200, {}))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == set()
    assert len(calls) == 1
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_breach_house_categories_are_kept_apart(monkeypatch: pytest.MonkeyPatch, provider_session: ProviderSession) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    calls = respond(
        monkeypatch,
        search_result(
            ransomware=[record(1, 'Example Corp', 'akira', website='example.com')],
            breaches=[record(2, 'example.com customers', 'DBs Backup')],
            leads=[record(3, 'Example VPN access', 'broker', website='vpn.example.com')],
            stealers=[record(4, '', 'lumma', website='example.com')],
        ),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process(proxy=True) is None
    assert await search.get_breach_names() == {
        f'Example Corp (akira) [{BREACH_HOUSE} | ransomware leak]',
        f'example.com customers (DBs Backup) [{BREACH_HOUSE} | data breach]',
        f'Example VPN access (broker) [{BREACH_HOUSE} | access lead]',
        f'example.com (lumma) [{BREACH_HOUSE} | stealer log]',
    }
    assert [call['url'] for call in calls] == [BREACH_HOUSE_URL]
    assert provider_session.kwargs == [
        {'headers': {'Accept': 'application/json', 'Authorization': 'Bearer bh-key'}, 'proxy': True, 'request_timeout': 60}
    ]
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_breach_house_records_of_other_domains_are_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    respond(
        monkeypatch,
        search_result(
            ransomware=[
                record(1, 'Example Corp', 'akira', website='example.com'),
                # The search matches free text, so a description that names the target is not a leak of it.
                record(2, 'Other Corp', 'play', website='other.com'),
                record(3, 'Not example.com', 'qilin', website='notexample.com'),
            ],
            breaches=[record(4, 'Unrelated dump', 'channel')],
        ),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {f'Example Corp (akira) [{BREACH_HOUSE} | ransomware leak]'}


@pytest.mark.asyncio
async def test_both_products_are_queried_and_shared_records_reported_once(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    calls = respond(
        monkeypatch,
        page([leak('101', 'Example Corp', 'akira', website='example.com')]),
        search_result(
            # The same victim Have I Been Ransomed? returned, and a second listing by another group.
            ransomware=[
                record(1, 'Example Corp', 'akira', website='example.com', discovered='2024-01-01 08:00:00'),
                record(2, 'Example Corp', 'qilin', website='example.com'),
            ],
            stealers=[record(3, 'example.com', 'lumma', website='example.com')],
        ),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() is None
    assert await search.get_breach_names() == {
        f'Example Corp (akira) [{HIBR} | ransomware leak]',
        f'Example Corp (qilin) [{BREACH_HOUSE} | ransomware leak]',
        f'example.com (lumma) [{BREACH_HOUSE} | stealer log]',
    }
    assert [call['url'] for call in calls] == [BASE_URL, BREACH_HOUSE_URL]
    assert [kwargs['headers']['Authorization'] for kwargs in provider_session.kwargs] == ['Bearer hibr-key', 'Bearer bh-key']
    assert provider_session.lifecycle == ['open', 'close', 'open', 'close']


@pytest.mark.asyncio
async def test_a_failing_product_keeps_the_results_of_the_other(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    respond(
        monkeypatch,
        FetcherResponse(None, 401, {}),
        search_result(ransomware=[record(1, 'Example Corp', 'akira', website='example.com')]),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'access-denied')
    assert await search.get_breach_names() == {f'Example Corp (akira) [{BREACH_HOUSE} | ransomware leak]'}


@pytest.mark.asyncio
async def test_a_failure_is_reported_ahead_of_incomplete_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(darkeye.SearchDarkEye, 'MAX_PAGES', 1)
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    respond(monkeypatch, page([leak('1', 'Example A', 'akira')], has_next=True), FetcherResponse(None, 429, {}))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('rate-limited', 'http-429')
    assert await search.get_breach_names() == {f'Example A (akira) [{HIBR} | ransomware leak]'}


@pytest.mark.asyncio
async def test_breach_house_limit_follows_the_result_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    calls = respond(
        monkeypatch,
        search_result(
            ransomware=[record(1, 'Example A', 'akira', website='example.com'), record(2, 'Example B', 'play', website='example.com')]
        ),
    )
    search = darkeye.SearchDarkEye('example.com', limit=1)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_breach_names() == {f'Example A (akira) [{BREACH_HOUSE} | ransomware leak]'}
    assert calls[0]['url'] == 'https://breach.house/api/v1/search?q=example.com&limit=1'


@pytest.mark.asyncio
async def test_breach_house_is_skipped_once_the_result_limit_is_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    calls = respond(monkeypatch, page([leak('1', 'Example A', 'akira'), leak('2', 'Example B', 'play')], has_next=True))
    search = darkeye.SearchDarkEye('example.com', limit=1)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_breach_house_truncation_reports_incomplete_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    body = search_result(ransomware=[record(1, 'Example A', 'akira', website='example.com')]).body
    body['ransomware']['total'] = 250
    respond(monkeypatch, FetcherResponse(body, 200, {}))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('partial', 'provider-limit')
    assert await search.get_breach_names() == {f'Example A (akira) [{BREACH_HOUSE} | ransomware leak]'}


@pytest.mark.parametrize(
    'body',
    [
        None,
        [],
        {},
        {'error': 'invalid_token'},
        {'ransomware': 'many'},
        {'ransomware': {'results': 'many', 'total': 1}},
    ],
)
@pytest.mark.asyncio
async def test_malformed_breach_house_payloads_are_reported(monkeypatch: pytest.MonkeyPatch, body: Any) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    respond(monkeypatch, FetcherResponse(body, 200, {}))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == set()


@pytest.mark.asyncio
async def test_malformed_breach_house_records_keep_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    use_keys(monkeypatch, None, 'bh-key')
    respond(monkeypatch, search_result(ransomware=[record(1, 'Example Corp', 'akira', website='example.com'), 'bad', {'id': 2}]))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == {f'Example Corp (akira) [{BREACH_HOUSE} | ransomware leak]'}


@pytest.mark.parametrize('keys', [(None, None), ('', ''), ('  ', None), (None, '\t')])
def test_missing_or_blank_keys_fail_closed(monkeypatch: pytest.MonkeyPatch, keys: tuple[str | None, str | None]) -> None:
    use_keys(monkeypatch, *keys)
    with pytest.raises(MissingKey):
        darkeye.SearchDarkEye('example.com')


@pytest.mark.parametrize(
    ('configured', 'ready'),
    [
        ({}, False),
        ({'haveibeenransom_key': '', 'breachhouse_key': ' '}, False),
        ({'haveibeenransom_key': 'hibr-key', 'breachhouse_key': None}, True),
        ({'breachhouse_key': 'bh-key'}, True),
    ],
)
def test_either_product_key_makes_the_source_ready(configured: dict, ready: bool) -> None:
    assert Core.api_key_ready('darkeye', configured) is ready
    assert Core.api_key_ready('fofa', {'key': 'fofa-key', 'email': ''}) is False


@pytest.mark.parametrize('target', ['', '*.example.com', 'exam?le.com', 'example', '192.0.2.1', 'example.com/path'])
@pytest.mark.asyncio
async def test_targets_that_are_not_domains_are_rejected_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    target: str,
) -> None:
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    calls = respond(monkeypatch)
    search = darkeye.SearchDarkEye(target)

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
@pytest.mark.parametrize('keys', [('hibr-key', None), (None, 'bh-key')])
@pytest.mark.asyncio
async def test_http_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    status: int,
    report: SourceExecutionReport,
    keys: tuple[str | None, str | None],
) -> None:
    use_keys(monkeypatch, *keys)
    respond(monkeypatch, FetcherResponse(None, status, {}))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == report
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.asyncio
async def test_a_failure_on_a_later_page_keeps_earlier_results(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(
        monkeypatch,
        page([leak('1', 'Example Corp', 'akira')], has_next=True),
        FetcherResponse(None, 429, {}),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('rate-limited', 'http-429')
    assert await search.get_breach_names() == {f'Example Corp (akira) [{HIBR} | ransomware leak]'}


@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
@pytest.mark.parametrize('keys', [('hibr-key', None), (None, 'bh-key')])
@pytest.mark.asyncio
async def test_bounded_fetch_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    reason: str,
    keys: tuple[str | None, str | None],
) -> None:
    use_keys(monkeypatch, *keys)
    respond(monkeypatch, ResponseStreamError(reason))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', reason)
    assert provider_session.lifecycle == ['open', 'close']


@pytest.mark.parametrize('failure_point', ['open', 'close'])
@pytest.mark.parametrize('keys', [('hibr-key', None), (None, 'bh-key')])
@pytest.mark.asyncio
async def test_session_lifecycle_failures_are_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    keys: tuple[str | None, str | None],
) -> None:
    @contextlib.asynccontextmanager
    async def failing_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    use_keys(monkeypatch, *keys)
    monkeypatch.setattr(darkeye.AsyncFetcher, 'open_session', failing_open_session)
    respond(monkeypatch, page([]) if keys[0] else search_result())
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_cancellation_propagates_and_closes_the_session(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    use_keys(monkeypatch, 'hibr-key', 'bh-key')
    respond(monkeypatch, page([leak('1', 'Example Corp', 'akira')], has_next=True), darkeye.asyncio.CancelledError())
    search = darkeye.SearchDarkEye('example.com')

    with pytest.raises(darkeye.asyncio.CancelledError):
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
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == set()


@pytest.mark.asyncio
async def test_malformed_entries_keep_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example Corp', 'akira'), 'bad', {'id_source': '2', 'post_title': 7}]))
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await search.get_breach_names() == {f'Example Corp (akira) [{HIBR} | ransomware leak]'}


@pytest.mark.asyncio
async def test_result_limit_stops_before_the_next_page(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = respond(
        monkeypatch,
        page([leak('1', 'Example A', 'akira'), leak('2', 'Example B', 'play')], has_next=True),
        page([leak('3', 'Example C', 'akira')], number=2),
    )
    search = darkeye.SearchDarkEye('example.com', limit=2)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_breach_names() == {
        f'Example A (akira) [{HIBR} | ransomware leak]',
        f'Example B (play) [{HIBR} | ransomware leak]',
    }
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_result_limit_inside_a_page_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example A', 'akira'), leak('2', 'Example A', 'akira'), leak('3', 'Example B', 'play')]))
    search = darkeye.SearchDarkEye('example.com', limit=1)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_breach_names() == {f'Example A (akira) [{HIBR} | ransomware leak]'}


@pytest.mark.asyncio
async def test_reaching_the_limit_on_the_last_page_completes_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, page([leak('1', 'Example A', 'akira'), leak('2', 'Example B', 'play')]))
    search = darkeye.SearchDarkEye('example.com', limit=2)

    assert await search.process() is None
    assert await search.get_breach_names() == {
        f'Example A (akira) [{HIBR} | ransomware leak]',
        f'Example B (play) [{HIBR} | ransomware leak]',
    }


@pytest.mark.asyncio
async def test_page_guard_reports_incomplete_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(darkeye.SearchDarkEye, 'MAX_PAGES', 2)
    calls = respond(
        monkeypatch,
        page([leak('1', 'Example A', 'akira')], has_next=True),
        page([leak('2', 'Example B', 'play')], has_next=True, number=2),
    )
    search = darkeye.SearchDarkEye('example.com')

    assert await search.process() == SourceExecutionReport('partial', 'provider-limit')
    assert await search.get_breach_names() == {
        f'Example A (akira) [{HIBR} | ransomware leak]',
        f'Example B (play) [{HIBR} | ransomware leak]',
    }
    assert len(calls) == 2
