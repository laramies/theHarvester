import contextlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from aiohttp import ClientSession, web

from theHarvester.discovery import searchapisearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

NEXT_PAGE = 'https://www.google.com/search?q=site%3Aexample.com&start=10'


def _result(index: int) -> dict[str, Any]:
    return {
        'position': index + 1,
        'title': f'Result {index}',
        'link': f'https://host-{index}.example.com/page',
        'snippet': f'host-{index}.example.com',
        'source': 'Example',
        'domain': f'host-{index}.example.com',
        'displayed_link': f'https://host-{index}.example.com › page',
    }


def _redirect(index: int) -> dict[str, Any]:
    """A lower-ranked row Google serves through google.com/goto with an opaque token."""
    return {
        'position': index + 1,
        'title': f'Redirected {index}',
        'link': f'https://www.google.com/goto?url=CAESW{index}opaque&gsessionid=session-{index}',
        'link_token': f'token-{index}',
        'snippet': f'Redirect snippet {index}',
        'source': 'Example',
        'domain': f'redirect-{index}.example.com',
        'displayed_link': f'https://redirect-{index}.example.com › docs › page-{index}',
    }


def _response(results: list[dict[str, Any]] | None, *, next_page: str | None = NEXT_PAGE, page: int = 1) -> FetcherResponse:
    body: dict[str, Any] = {
        'search_metadata': {'id': 'search_test', 'status': 'Success'},
        'search_parameters': {'engine': 'google', 'q': 'site:example.com', 'page': str(page)},
        'pagination': {'current': page},
    }
    if results is not None:
        body['organic_results'] = results
    if next_page:
        body['pagination']['next'] = next_page
    return FetcherResponse(body, 200, {})


def _no_results() -> FetcherResponse:
    """SearchApi answers a query without results with HTTP 200, the envelope and an error string."""
    return FetcherResponse(
        {
            'search_metadata': {'id': 'search_test', 'status': 'Success'},
            'search_parameters': {'engine': 'google', 'q': 'site:example.com'},
            'error': "Google didn't return any results.",
        },
        200,
        {},
    )


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


def search_headers(search: searchapisearch.SearchSearchApi) -> dict[str, str]:
    return {
        'Accept': 'application/json',
        'Authorization': f'Bearer {search.api_key}',
    }


@pytest.fixture
def searchapi_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'searchapi': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_searchapi_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(searchapisearch.asyncio, 'sleep', no_sleep)


def test_searchapi_requires_an_api_key() -> None:
    with pytest.raises(MissingKey, match='SearchApi'):
        searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=InMemoryCredentialAdapter({}))


def test_searchapi_treats_a_blank_key_as_missing() -> None:
    with pytest.raises(MissingKey, match='SearchApi'):
        searchapisearch.SearchSearchApi(
            'example.com',
            10,
            credential_adapter=InMemoryCredentialAdapter({'searchapi': {'key': ''}}),
        )


@pytest.mark.asyncio
async def test_searchapi_normalizes_in_scope_evidence(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'position': 1,
                        'title': 'Contact Admin@Example.COM.',
                        'link': 'https://Blog.Example.COM./contact',
                        'snippet': 'Ignore outsider@example.net and api.example.net',
                        'domain': 'Blog.Example.COM',
                        'displayed_link': 'https://Blog.Example.COM › contact',
                    }
                ],
                next_page=None,
            ),
            _no_results(),
        ]
    )

    request_urls: list[str] = []
    request_proxies: list[bool | None] = []
    request_sessions: list[object] = []
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

    async def fake_fetch(url: str, **kwargs: Any) -> FetcherResponse:
        request_urls.append(url)
        request_proxies.append(kwargs.get('proxy'))
        request_sessions.append(kwargs.get('session'))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    report = await search.process(proxy=True)

    assert report is None
    assert session_options == [{'headers': search_headers(search), 'proxy': True, 'request_timeout': 60}]
    assert request_proxies == [None, None]
    assert request_sessions == [owned_session, owned_session]
    assert lifecycle == ['open', 'close']
    assert all(url.startswith('https://www.searchapi.io/api/v1/search?') for url in request_urls)
    assert all('test-token' not in url for url in request_urls), 'the key travels only in the Authorization header'
    assert [_query(url) for url in request_urls] == [
        {'engine': ['google'], 'q': ['"example.com"'], 'page': ['1']},
        {'engine': ['google'], 'q': ['site:example.com'], 'page': ['1']},
    ]
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.asyncio
async def test_searchapi_takes_redirect_row_hosts_from_the_row_not_from_google(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """google.com/goto rows carry an opaque token, so the host comes from domain and displayed_link."""

    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([_result(0), _redirect(1)], next_page=None)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() is None
    assert 'google.com' not in search.totalresults
    assert 'opaque' not in search.totalresults
    assert await search.get_hostnames() == ['host-0.example.com', 'redirect-1.example.com']
    assert [result['link'] for result in search.results] == [_result(0)['link'], _redirect(1)['link']]
    assert search.results[1]['domain'] == 'redirect-1.example.com'
    assert 'evidence' not in search.results[0]


@pytest.mark.asyncio
async def test_searchapi_deduplicates_redirect_rows_by_displayed_link_across_pages(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """Redirect tokens change between requests, so a repeated window is recognized by its displayed links."""

    page_one = [_redirect(index) for index in range(10)]
    # Page two repeats page one under fresh tokens and still advertises a next
    # page; page three is the no-results body that ends the query.
    page_two = [
        dict(_redirect(index), link=f'https://www.google.com/goto?url=OTHER{index}&gsessionid=later') for index in range(10)
    ]
    assert [row['link'] for row in page_one] != [row['link'] for row in page_two]
    responses = iter([_response(page_one), _response(page_two, page=2), _no_results(), _no_results()])
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', None, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['"example.com"'], ['2']),
        (['"example.com"'], ['3']),
        (['site:example.com'], ['1']),
    ]
    assert len(search.results) == 10
    assert report is None


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_point', ['open', 'close'])
async def test_searchapi_reports_session_lifecycle_failures(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    failure_point: str,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _no_results()

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'open_session', failed_open_session)
    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_searchapi_does_not_misclassify_value_errors_as_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        raise ValueError('programming defect')
        yield object()

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'open_session', failed_open_session)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    with pytest.raises(ValueError, match='programming defect'):
        await search.process()


@pytest.mark.parametrize('body', [None, []], ids=['empty', 'malformed'])
@pytest.mark.asyncio
async def test_searchapi_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    body: list[Any] | None,
) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    report = await search.process()

    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []
    assert report == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_report'),
    [
        (FetcherResponse(None, 401, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse(None, 402, {}), SourceExecutionReport('failed', 'http-402')),
        (FetcherResponse(None, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse(None, 503, {}), SourceExecutionReport('failed', 'http-503')),
    ],
)
async def test_searchapi_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    response: FetcherResponse,
    expected_report: SourceExecutionReport,
) -> None:
    calls: list[object] = []

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        calls.append(object())
        return response

    async def legacy_fetch(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('SearchApi must use the bounded fetch_json seam')

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch', legacy_fetch)

    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() == expected_report
    assert len(calls) == 1
    assert search.totalresults == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_searchapi_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_searchapi_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise searchapisearch.asyncio.CancelledError

    lifecycle: list[str] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        lifecycle.append('open')
        try:
            yield object()
        finally:
            lifecycle.append('close')

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    with pytest.raises(searchapisearch.asyncio.CancelledError):
        await search.process()

    assert lifecycle == ['open', 'close']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        {},
        {'organic_results': []},
        {'search_metadata': 'invalid', 'organic_results': []},
        {'search_metadata': {}, 'organic_results': 'invalid'},
        {'search_metadata': {}, 'organic_results': ['invalid']},
    ],
    ids=['no-envelope', 'rows-without-envelope', 'envelope-not-a-mapping', 'rows-not-a-list', 'row-not-a-mapping'],
)
async def test_searchapi_reports_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    body: dict[str, Any],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['title', 'snippet', 'link', 'domain', 'displayed_link'])
async def test_searchapi_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    field: str,
) -> None:
    result: dict[str, object] = _result(1)
    result[field] = {'unexpected': 'host.example.com'}

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([result])

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
async def test_searchapi_tolerates_optional_fields_and_skips_rows_without_a_host(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response(
            [
                {'position': 1, 'link': 'https://www.example.com/', 'title': None},
                {'position': 2, 'title': 'neither link nor domain', 'snippet': 'orphan.example.com'},
            ],
            next_page=None,
        )

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() is None
    assert search.results == [
        {'title': '', 'snippet': '', 'link': 'https://www.example.com/', 'domain': '', 'displayed_link': ''},
    ]
    assert await search.get_hostnames() == ['www.example.com']


@pytest.mark.asyncio
async def test_searchapi_treats_a_query_without_results_as_a_normal_end(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """A no-results answer is HTTP 200 with the envelope, an error string and no organic_results."""

    requests: list[dict[str, list[str]]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return _no_results()

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() is None
    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['site:example.com'], ['1']),
    ]
    assert search.totalresults == ''
    assert await search.get_hostnames() == []


@pytest.mark.asyncio
async def test_searchapi_stops_a_query_at_a_page_past_the_last_one(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """A page past the end keeps the envelope and pagination but has no organic_results."""

    responses = iter([_response([_result(index) for index in range(10)]), _response(None, next_page=None, page=2), _no_results()])
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = searchapisearch.SearchSearchApi('example.com', None, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['"example.com"'], ['2']),
        (['site:example.com'], ['1']),
    ]
    assert len(search.results) == 10
    assert report is None


@pytest.mark.asyncio
async def test_searchapi_paginates_with_page_numbers_and_one_global_limit(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """Pages are numbered from one and the adapter never sends num: Google caps a page at ten rows."""

    responses = iter(
        [
            _response([_result(index) for index in range(10)]),
            _response([_result(index) for index in range(10, 20)], page=2),
            _response([_result(index) for index in range(20, 30)], page=3),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 25, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert requests == [
        {'engine': ['google'], 'q': ['"example.com"'], 'page': ['1']},
        {'engine': ['google'], 'q': ['"example.com"'], 'page': ['2']},
        {'engine': ['google'], 'q': ['"example.com"'], 'page': ['3']},
    ]
    assert len(search.results) == 25
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
@pytest.mark.parametrize('second_page', [range(5, 15), range(8, 18)], ids=['overlap-5', 'overlap-8'])
async def test_searchapi_keeps_fresh_rows_from_an_overlapping_final_page(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
    second_page: range,
) -> None:
    """Rows are deduplicated across the whole page before the limit trims them."""

    responses = iter(
        [
            _response([_result(index) for index in range(10)]),
            _response([_result(index) for index in second_page], page=2),
        ]
    )
    requests: list[dict[str, list[str]]] = []
    borrowed_sessions: list[object] = []
    owned_session = object()

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        yield owned_session

    async def fake_fetch(url: str, **kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        borrowed_sessions.append(kwargs.get('session'))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 15, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [request['page'] for request in requests] == [['1'], ['2']]
    assert borrowed_sessions == [owned_session, owned_session]
    assert [result['link'] for result in search.results] == [_result(index)['link'] for index in range(15)]
    assert search.totalresults.count('\n') == 15
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_searchapi_follows_next_past_a_page_that_only_repeats_earlier_links(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """A window that only repeats earlier rows is not exhaustion: while next is advertised, the query goes on."""

    responses = iter(
        [
            _response([_result(index) for index in range(10)]),
            _response([_result(index) for index in range(10)], page=2),
            _response([_result(10), _result(11)], next_page=None, page=3),
            _no_results(),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', None, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['"example.com"'], ['2']),
        (['"example.com"'], ['3']),
        (['site:example.com'], ['1']),
    ]
    assert [result['link'] for result in search.results] == [_result(index)['link'] for index in range(12)]
    assert search.totalresults.count('\n') == 12
    assert report is None


@pytest.mark.asyncio
async def test_searchapi_keeps_new_text_from_a_link_repeated_within_one_query(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """A later page of the same query can repeat a link with a snippet that carries new evidence."""

    responses = iter(
        [
            _response([dict(_result(1), snippet='one.example.com')]),
            _response(
                [dict(_result(1), snippet='Contact admin@example.com or two.example.com'), _result(2)],
                next_page=None,
                page=2,
            ),
            _no_results(),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 5, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['"example.com"'], ['2']),
        (['site:example.com'], ['1']),
    ]
    # The repeated link counts once; both of its snippets reach the parser.
    assert [result['link'] for result in search.results] == [_result(1)['link'], _result(2)['link']]
    assert search.totalresults.count('\n') == 3
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == [
        'example.com',
        'host-1.example.com',
        'host-2.example.com',
        'one.example.com',
        'two.example.com',
    ]
    assert report is None


@pytest.mark.asyncio
async def test_searchapi_counts_a_link_once_across_queries_but_parses_its_new_text(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """The site: query can return a link the exact-match query already counted, with a different snippet."""

    responses = iter(
        [
            _response([dict(_result(1), snippet='one.example.com')], next_page=None),
            _response([dict(_result(1), snippet='Contact admin@example.com or two.example.com'), _result(2)], next_page=None),
        ]
    )

    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 5, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [result['link'] for result in search.results] == [_result(1)['link'], _result(2)['link']]
    assert search.totalresults.count('\n') == 3
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == [
        'example.com',
        'host-1.example.com',
        'host-2.example.com',
        'one.example.com',
        'two.example.com',
    ]
    assert report is None


@pytest.mark.asyncio
async def test_searchapi_fills_the_limit_after_links_repeated_from_the_first_query(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """Links the site: query repeats do not use up the allowance, so later fresh rows still fit."""

    responses = iter(
        [
            _response([_result(index) for index in range(7)], next_page=None),
            _response([_result(index) for index in range(10)], next_page=None),
        ]
    )

    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 9, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [result['link'] for result in search.results] == [_result(index)['link'] for index in range(9)]
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_searchapi_stops_a_query_when_no_next_page_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """A full page without pagination.next is the last page; the adapter does not probe further."""

    responses = iter(
        [
            _response([_result(index) for index in range(10)], next_page=None),
            _response([_result(index) for index in range(10, 20)], next_page=None),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', None, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['site:example.com'], ['1']),
    ]
    assert len(search.results) == 20
    assert report is None


@pytest.mark.asyncio
async def test_searchapi_stops_a_query_on_an_empty_page(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter([_response([_result(1)]), _response([]), _response([_result(2)], next_page=None)])
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return next(responses, _no_results())

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)

    assert await search.process() is None
    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], ['1']),
        (['"example.com"'], ['2']),
        (['site:example.com'], ['1']),
    ]
    assert len(search.results) == 2


@pytest.mark.asyncio
async def test_searchapi_trims_surplus_rows_without_asking_for_fewer(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """Every request is billed the same, so a whole page is fetched and trimmed locally."""

    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return _response([_result(index) for index in range(10)])

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 3, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert requests == [{'engine': ['google'], 'q': ['"example.com"'], 'page': ['1']}]
    assert len(search.results) == 3
    assert search.totalresults.count('\n') == 3
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_searchapi_reports_the_page_boundary_as_truncation_when_unlimited(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    """Ten pages still advertising a next page bound the query; the other query runs and the result is partial."""

    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        page = len(requests)
        return _response([_result(page * 10 + index) for index in range(10)], page=page)

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', None, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [(request['q'], request['page']) for request in requests] == [
        (['"example.com"'], [str(page)]) for page in range(1, 11)
    ] + [(['site:example.com'], [str(page)]) for page in range(1, 11)]
    assert len(search.results) == 200
    assert report == SourceExecutionReport('partial', 'provider-limit')


@pytest.mark.asyncio
async def test_searchapi_stops_after_an_exact_full_page(
    monkeypatch: pytest.MonkeyPatch,
    searchapi_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_query(url))
        return _response([_result(index) for index in range(10)])

    monkeypatch.setattr(searchapisearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = searchapisearch.SearchSearchApi('example.com', 10, credential_adapter=searchapi_credentials)
    report = await search.process()

    assert [request['page'] for request in requests] == [['1']]
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_searchapi_pagination_reuses_one_session_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    """A later page depends on a cookie the first page set, and the owned session closes afterwards."""

    requests: list[tuple[str | None, str | None, str | None]] = []
    sessions: list[ClientSession] = []
    original_build_session = searchapisearch.AsyncFetcher._build_session

    async def tracked_build_session(*args: object, **kwargs: object) -> ClientSession:
        session = await original_build_session(*args, **kwargs)  # type: ignore[arg-type]
        sessions.append(session)
        return session

    monkeypatch.setattr(searchapisearch.AsyncFetcher, '_build_session', tracked_build_session)

    async def search(request: web.Request) -> web.Response:
        page = request.query.get('page')
        requests.append((page, request.cookies.get('provider-session'), request.headers.get('Authorization')))
        if page == '1':
            response = web.json_response(
                {
                    'search_metadata': {'status': 'Success'},
                    'organic_results': [_result(1)],
                    'pagination': {'current': 1, 'next': NEXT_PAGE},
                }
            )
            response.set_cookie('provider-session', 'ready')
            return response
        if request.cookies.get('provider-session') != 'ready':
            return web.json_response({'error': 'missing provider session'}, status=403)
        return web.json_response(
            {
                'search_metadata': {'status': 'Success'},
                'organic_results': [_result(2)],
                'pagination': {'current': 2},
            }
        )

    app = web.Application()
    app.router.add_get('/search', search)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', unused_tcp_port)
    await site.start()

    try:
        source = searchapisearch.SearchSearchApi(
            'example.com',
            limit=2,
            credential_adapter=InMemoryCredentialAdapter({'searchapi': {'key': 'test-token'}}),
        )
        source.server = f'http://localhost:{unused_tcp_port}/search'
        report = await source.process()
    finally:
        await runner.cleanup()

    assert requests == [('1', None, 'Bearer test-token'), ('2', 'ready', 'Bearer test-token')]
    assert await source.get_hostnames() == ['host-1.example.com', 'host-2.example.com']
    assert report == SourceExecutionReport('completed', 'result-limit')
    assert len(sessions) == 1
    assert sessions[0].closed is True


pytestmark = pytest.mark.provider_contract('searchapi')
