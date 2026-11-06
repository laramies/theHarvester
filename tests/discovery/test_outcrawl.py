import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import outcrawlsearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import MAX_PROVIDER_JSON_BYTES, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


def _hit(index: int) -> dict[str, Any]:
    return {
        'title': f'Result {index}',
        'snippet': f'host-{index}.example.com',
        'url': f'https://host-{index}.example.com',
        'rank': index + 1,
    }


def _response(hits: list[dict[str, Any]]) -> FetcherResponse:
    return FetcherResponse({'hits': hits, 'usage': {'credits': '0.5'}}, 200, {})


def search_headers(search: outcrawlsearch.SearchOutcrawl) -> dict[str, str]:
    return {
        'Accept': 'application/json',
        'Authorization': f'Bearer {search.api_key}',
        'Content-Type': 'application/json',
    }


@pytest.fixture
def outcrawl_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'outcrawl': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_outcrawl_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(outcrawlsearch.asyncio, 'sleep', no_sleep)


def test_outcrawl_requires_an_api_key() -> None:
    with pytest.raises(MissingKey, match='Outcrawl'):
        outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=InMemoryCredentialAdapter({}))


def test_outcrawl_treats_a_blank_key_as_missing() -> None:
    with pytest.raises(MissingKey, match='Outcrawl'):
        outcrawlsearch.SearchOutcrawl(
            'example.com',
            10,
            credential_adapter=InMemoryCredentialAdapter({'outcrawl': {'key': ''}}),
        )


@pytest.mark.asyncio
async def test_outcrawl_normalizes_in_scope_evidence(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'title': 'Contact Admin@Example.COM.',
                        'snippet': 'Ignore outsider@example.net and api.example.net',
                        'url': 'https://Blog.Example.COM./contact',
                        'rank': 1,
                    }
                ]
            ),
            _response([]),
        ]
    )

    request_kwargs: list[dict[str, Any]] = []
    session_options: list[dict[str, Any]] = []
    lifecycle: list[str] = []
    owned_session = object()

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        session_options.append(kwargs)
        lifecycle.append('open')
        try:
            yield owned_session
        finally:
            lifecycle.append('close')

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        request_kwargs.append(kwargs)
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    await search.process(proxy=True)

    assert session_options == [{'headers': search_headers(search), 'proxy': True, 'request_timeout': 60}]
    assert [kwargs.get('proxy') for kwargs in request_kwargs] == [None, None]
    assert [kwargs['session'] for kwargs in request_kwargs] == [owned_session, owned_session]
    assert all(kwargs['response_byte_limit'] == MAX_PROVIDER_JSON_BYTES for kwargs in request_kwargs)
    assert lifecycle == ['open', 'close']
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_point', ['open', 'close'])
async def test_outcrawl_reports_session_lifecycle_failures(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    failure_point: str,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([])

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'open_session', failed_open_session)
    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_outcrawl_does_not_misclassify_value_errors_as_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        raise ValueError('programming defect')
        yield object()

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'open_session', failed_open_session)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    with pytest.raises(ValueError, match='programming defect'):
        await search.process()


@pytest.mark.parametrize('body', [None, [], 'not json'], ids=['empty', 'malformed', 'text'])
@pytest.mark.asyncio
async def test_outcrawl_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    body: Any,
) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    report = await search.process()

    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []
    assert report == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_report'),
    [
        (None, SourceExecutionReport('failed', 'transport-error')),
        (FetcherResponse(None, 401, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse(None, 402, {}), SourceExecutionReport('failed', 'http-402')),
        (FetcherResponse(None, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse(None, 503, {}), SourceExecutionReport('failed', 'http-503')),
    ],
)
async def test_outcrawl_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    response: FetcherResponse | None,
    expected_report: SourceExecutionReport,
) -> None:
    calls: list[object] = []

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        calls.append(object())
        return response

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() == expected_report
    assert len(calls) == 1
    assert search.totalresults == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_outcrawl_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    reason: str,
) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_outcrawl_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise outcrawlsearch.asyncio.CancelledError

    lifecycle: list[str] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        lifecycle.append('open')
        try:
            yield object()
        finally:
            lifecycle.append('close')

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    with pytest.raises(outcrawlsearch.asyncio.CancelledError):
        await search.process()

    assert lifecycle == ['open', 'close']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        {},
        {'hits': 'invalid'},
        {'hits': ['invalid']},
    ],
)
async def test_outcrawl_reports_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    body: dict[str, Any],
) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['title', 'snippet', 'url'])
async def test_outcrawl_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
    field: str,
) -> None:
    hit: dict[str, object] = _hit(1)
    hit[field] = {'unexpected': 'host.example.com'}

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'hits': [hit]}, 200, {})

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
async def test_outcrawl_tolerates_missing_title_and_snippet(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([{'url': 'https://www.example.com/', 'title': None}, {'title': 'no url'}])

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)

    assert await search.process() is None
    assert search.results == [{'title': '', 'snippet': '', 'url': 'https://www.example.com/'}]
    assert await search.get_hostnames() == ['www.example.com']


@pytest.mark.asyncio
async def test_outcrawl_sends_one_request_per_query_with_the_result_limit(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    """Outcrawl has no offset parameter, so each query is one request; the second leaves room for repeats."""

    responses = iter(
        [
            _response([_hit(index) for index in range(12)]),
            _response([_hit(index) for index in range(12, 20)]),
        ]
    )
    requests: list[tuple[str, dict[str, Any]]] = []

    async def fake_post_fetch(url: str, **kwargs: Any) -> FetcherResponse:
        requests.append((url, kwargs['json_body']))
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 30, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert requests == [
        ('https://api.outcrawl.ai/v1/search', {'query': '"example.com"', 'limit': 20}),
        ('https://api.outcrawl.ai/v1/search', {'query': 'site:example.com', 'limit': 20}),
    ]
    assert len(search.results) == 20
    assert report is None


@pytest.mark.asyncio
async def test_outcrawl_reports_capped_full_windows_as_partial(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    """Two full twenty-hit windows may hide further hits, so coverage is partial, not complete."""
    requests: list[dict[str, Any]] = []

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        requests.append(kwargs['json_body'])
        offset = len(requests) * 100
        return _response([_hit(offset + index) for index in range(20)])

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', None, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert requests == [
        {'query': '"example.com"', 'limit': 20},
        {'query': 'site:example.com', 'limit': 20},
    ]
    assert len(search.results) == 40
    assert report == SourceExecutionReport('partial', 'provider-limit')


@pytest.mark.asyncio
async def test_outcrawl_deduplicates_links_across_queries(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_hit(index) for index in range(5)]),
            _response([_hit(index) for index in range(3, 8)]),
        ]
    )

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert [result['url'] for result in search.results] == [_hit(index)['url'] for index in range(8)]
    assert search.totalresults.count('\n') == 8
    assert report is None


@pytest.mark.asyncio
async def test_outcrawl_trims_surplus_rows_and_stops_at_the_limit(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, Any]] = []

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        requests.append(kwargs['json_body'])
        return _response([_hit(index) for index in range(10)])

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 3, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert requests == [{'query': '"example.com"', 'limit': 3}]
    assert len(search.results) == 3
    assert report == SourceExecutionReport('completed', 'result-limit')



@pytest.mark.asyncio
async def test_outcrawl_fills_the_limit_after_an_overlapping_prefix(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    """17 links, then a window that repeats all 17 before new ones, still reaches a limit of 20."""

    requests: list[dict[str, Any]] = []
    responses = iter(
        [
            _response([_hit(index) for index in range(17)]),
            _response([_hit(index) for index in range(17)] + [_hit(index) for index in range(17, 20)]),
        ]
    )

    async def fake_post_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        requests.append(kwargs['json_body'])
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 20, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert requests == [
        {'query': '"example.com"', 'limit': 20},
        {'query': 'site:example.com', 'limit': 20},
    ]
    assert [result['url'] for result in search.results] == [_hit(index)['url'] for index in range(20)]
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_outcrawl_short_windows_complete_without_a_stop_reason(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    """Windows shorter than requested mean both queries were exhausted, unlike capped or limited runs."""

    responses = iter([_response([_hit(index) for index in range(19)]), _response([_hit(30)])])

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', None, credential_adapter=outcrawl_credentials)

    assert await search.process() is None
    assert len(search.results) == 20


@pytest.mark.asyncio
async def test_outcrawl_parses_new_evidence_from_a_repeated_link(
    monkeypatch: pytest.MonkeyPatch,
    outcrawl_credentials: InMemoryCredentialAdapter,
) -> None:
    """The same URL with a different snippet counts once but its new hostnames and emails are kept."""

    page = 'https://www.example.com/team'
    responses = iter(
        [
            _response([{'title': 'Team', 'snippet': 'mail.example.com', 'url': page}]),
            _response(
                [
                    {'title': 'Team', 'snippet': 'mail.example.com', 'url': page},
                    {'title': 'Team', 'snippet': 'Write to ops@example.com via vpn.example.com', 'url': page},
                ]
            ),
        ]
    )

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(outcrawlsearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = outcrawlsearch.SearchOutcrawl('example.com', 10, credential_adapter=outcrawl_credentials)
    report = await search.process()

    assert search.results == [{'title': 'Team', 'snippet': 'mail.example.com', 'url': page}]
    assert search.totalresults.count('\n') == 2
    assert 'ops@example.com' in await search.get_emails()
    assert {'mail.example.com', 'vpn.example.com'} <= set(await search.get_hostnames())
    assert report is None


pytestmark = pytest.mark.provider_contract('outcrawl')
