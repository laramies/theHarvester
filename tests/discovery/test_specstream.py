import contextlib
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import pytest
from aiohttp import ClientSession, web

from theHarvester.discovery import specstreamsearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.lib.source_runner import SOURCE_FACTORIES, SourceRequest, run_source

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from theHarvester.lib.core import StreamErrorReason


def _source(index: int) -> dict[str, Any]:
    return {
        'url': f'https://host-{index}.example.com',
        'title': f'Result {index}',
        'site': f'host-{index}.example.com',
        'snippet': f'host-{index}.example.com',
        'cited': False,
        'published': None,
    }


def _response(sources: list[object], next_page: object = None) -> FetcherResponse:
    return FetcherResponse({'data': {'query': 'q', 'sources': sources, 'next_page': next_page}}, 200, {})


def _params(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def search_headers(search: specstreamsearch.SearchSpecstream) -> dict[str, str]:
    return {'Accept': 'application/json', 'Authorization': f'Bearer {search.api_key}'}


@pytest.fixture
def specstream_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'specstream': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_specstream_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(specstreamsearch, 'get_delay', lambda: 0)


def test_specstream_requires_an_api_key() -> None:
    with pytest.raises(MissingKey, match='SpecStream'):
        specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=InMemoryCredentialAdapter({}))


def test_specstream_treats_a_blank_key_as_missing() -> None:
    with pytest.raises(MissingKey, match='SpecStream'):
        specstreamsearch.SearchSpecstream(
            'example.com',
            10,
            credential_adapter=InMemoryCredentialAdapter({'specstream': {'key': ''}}),
        )


@pytest.mark.asyncio
async def test_specstream_normalizes_in_scope_evidence(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'url': 'https://Blog.Example.COM./contact',
                        'title': 'Contact Admin@Example.COM.',
                        'site': 'blog.example.com',
                        'snippet': 'Ignore outsider@example.net and api.example.net',
                        'cited': False,
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

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        request_kwargs.append(kwargs)
        return next(responses)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process(proxy=True) is None

    assert session_options == [{'headers': search_headers(search), 'proxy': True, 'request_timeout': 60}]
    assert [kwargs.get('proxy') for kwargs in request_kwargs] == [None, None]
    assert [kwargs['session'] for kwargs in request_kwargs] == [owned_session, owned_session]
    assert lifecycle == ['open', 'close']
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_point', ['open', 'close'])
async def test_specstream_reports_session_lifecycle_failures(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    failure_point: str,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([])

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'open_session', failed_open_session)
    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_specstream_does_not_misclassify_value_errors_as_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        raise ValueError('programming defect')
        yield object()

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'open_session', failed_open_session)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    with pytest.raises(ValueError, match='programming defect'):
        await search.process()


@pytest.mark.parametrize('body', [None, [], 'not json'], ids=['empty', 'malformed', 'text'])
@pytest.mark.asyncio
async def test_specstream_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    body: Any,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

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
async def test_specstream_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    response: FetcherResponse | None,
    expected_report: SourceExecutionReport,
) -> None:
    calls: list[object] = []

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        calls.append(object())
        return response

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == expected_report
    assert len(calls) == 1
    assert search.totalresults == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_specstream_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    reason: StreamErrorReason,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_specstream_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise specstreamsearch.asyncio.CancelledError

    lifecycle: list[str] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        lifecycle.append('open')
        try:
            yield object()
        finally:
            lifecycle.append('close')

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    with pytest.raises(specstreamsearch.asyncio.CancelledError):
        await search.process()

    assert lifecycle == ['open', 'close']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        {},
        {'error': {'code': 'invalid_request', 'message': 'q is required'}},
        {'data': []},
        {'data': {}},
        {'data': {'sources': 'invalid'}},
        {'data': {'sources': ['invalid']}},
        {'data': {'sources': [], 'next_page': 'two'}},
        {'data': {'sources': [], 'next_page': 1}},
    ],
)
async def test_specstream_reports_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    body: dict[str, Any],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['title', 'snippet', 'url'])
@pytest.mark.parametrize('value', [False, 0, [], {}, {'unexpected': 'host.example.com'}])
async def test_specstream_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    field: str,
    value: object,
) -> None:
    source: dict[str, object] = _source(1)
    source[field] = value

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'data': {'sources': [source], 'next_page': None}}, 200, {})

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('limit', [3, 10])
@pytest.mark.parametrize('malformed', ['row', 'field', 'cursor'])
async def test_specstream_retains_valid_observations_on_a_malformed_page(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    limit: int,
    malformed: str,
) -> None:
    sources: list[object] = [_source(2), _source(3)]
    cursor: object = 3
    if malformed == 'row':
        sources.insert(1, 'discard.example.com')
    elif malformed == 'field':
        sources.insert(1, {**_source(4), 'title': False})
    else:
        cursor = True

    responses = iter([_response([_source(1)], next_page=2), _response(sources, next_page=cursor)])
    requests: list[dict[str, str]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_params(url))
        return next(responses)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setitem(
        SOURCE_FACTORIES,
        'specstream',
        lambda request: specstreamsearch.SearchSpecstream(request.target, request.limit, specstream_credentials),
    )

    outcome = await run_source(SourceRequest('specstream', 'example.com', limit, 0, False, True))

    assert outcome.execution.status == 'partial'
    assert outcome.execution.stop_reason == 'invalid-response'
    assert {observation.value for observation in outcome.observations} == {
        'host-1.example.com',
        'host-2.example.com',
        'host-3.example.com',
    }
    assert [(request['q'], request['page']) for request in requests] == [('"example.com"', '1'), ('"example.com"', '2')]


@pytest.mark.asyncio
async def test_specstream_tolerates_missing_title_and_snippet(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response(
            [
                {'url': 'https://www.example.com/', 'title': None},
                {'url': 'https://docs.example.com/', 'snippet': None},
                {'title': 'no url'},
                {'title': 'null url', 'url': None},
            ]
        )

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() is None
    assert search.results == [
        {'title': '', 'snippet': '', 'url': 'https://www.example.com/'},
        {'title': '', 'snippet': '', 'url': 'https://docs.example.com/'},
    ]
    assert await search.get_hostnames() == ['docs.example.com', 'www.example.com']


@pytest.mark.asyncio
async def test_specstream_pagination_preserves_provider_cookies_and_closes_the_session(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    unused_tcp_port: int,
) -> None:
    requests: list[tuple[dict[str, str], str | None, str | None]] = []
    sessions: list[ClientSession] = []
    create_session = specstreamsearch.AsyncFetcher.create_session

    async def tracked_create_session(**kwargs: Any) -> ClientSession:
        session = await create_session(**kwargs)
        sessions.append(session)
        return session

    async def provider_search(request: web.Request) -> web.Response:
        params = dict(request.query)
        cookie = request.cookies.get('provider-session')
        authorization = request.headers.get('Authorization')
        requests.append((params, cookie, authorization))
        if authorization != 'Bearer test-token':
            return web.json_response({'error': 'missing authorization'}, status=401)
        if (params['q'], params['page']) == ('"example.com"', '1'):
            response = web.json_response(_response([_source(index) for index in range(10)], next_page=2).body)
            response.set_cookie('provider-session', 'ready')
            return response
        if cookie != 'ready':
            return web.json_response({'error': 'missing provider session'}, status=403)
        indices = range(10, 14) if params['q'] == '"example.com"' else range(20, 23)
        return web.json_response(_response([_source(index) for index in indices]).body)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'create_session', tracked_create_session)
    app = web.Application()
    app.router.add_get('/search', provider_search)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.TCPSite(runner, '127.0.0.1', unused_tcp_port).start()
        search = specstreamsearch.SearchSpecstream('example.com', 18, credential_adapter=specstream_credentials)
        search.server = f'http://localhost:{unused_tcp_port}/search'
        report = await search.process()
    finally:
        await runner.cleanup()

    assert requests == [
        ({'q': '"example.com"', 'num': '10', 'page': '1', 'speed': 'fast'}, None, 'Bearer test-token'),
        ({'q': '"example.com"', 'num': '10', 'page': '2', 'speed': 'fast'}, 'ready', 'Bearer test-token'),
        ({'q': 'site:example.com', 'num': '4', 'page': '1', 'speed': 'fast'}, 'ready', 'Bearer test-token'),
    ]
    assert len(search.results) == 17
    assert report is None
    assert len(sessions) == 1
    assert sessions[0].closed


@pytest.mark.asyncio
async def test_specstream_reports_the_page_cap_as_partial(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    """A next_page past the provider's ten pages may hide further results, so coverage is partial."""

    pages: list[tuple[str, str]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        params = _params(url)
        pages.append((params['q'], params['page']))
        offset = len(pages) * 100
        return _response([_source(offset + index) for index in range(10)], next_page=int(params['page']) + 1)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', None, credential_adapter=specstream_credentials)
    report = await search.process()

    assert len(pages) == 20
    assert pages[9] == ('"example.com"', '10')
    assert pages[10] == ('site:example.com', '1')
    assert len(search.results) == 200
    assert report == SourceExecutionReport('partial', 'provider-limit')


@pytest.mark.asyncio
async def test_specstream_reaches_the_result_limit_after_the_first_query_hits_the_page_cap(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_source(1)], next_page=2),
            _response([_source(1)], next_page=3),
            _response([_source(1)], next_page=2),
            _response([_source(2)], next_page=3),
        ]
    )
    requests: list[dict[str, str]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_params(url))
        return next(responses)

    monkeypatch.setattr(specstreamsearch.SearchSpecstream, 'MAX_PAGES', 2)
    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 2, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert [(request['q'], request['page'], request['num']) for request in requests] == [
        ('"example.com"', '1', '2'),
        ('"example.com"', '2', '2'),
        ('site:example.com', '1', '1'),
        ('site:example.com', '2', '1'),
    ]
    assert [row['url'] for row in search.results] == ['https://host-1.example.com', 'https://host-2.example.com']


@pytest.mark.asyncio
async def test_specstream_deduplicates_links_across_queries(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_source(index) for index in range(5)]),
            _response([_source(index) for index in range(3, 8)]),
        ]
    )

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)
    report = await search.process()

    assert [result['url'] for result in search.results] == [_source(index)['url'] for index in range(8)]
    assert search.totalresults.count('\n') == 8
    assert report is None


@pytest.mark.asyncio
async def test_specstream_trims_surplus_rows_and_stops_at_the_limit(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, str]] = []

    async def fake_fetch_json(url: str, **_kwargs: Any) -> FetcherResponse:
        requests.append(_params(url))
        return _response([_source(index) for index in range(10)], next_page=2)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 3, credential_adapter=specstream_credentials)
    report = await search.process()

    assert requests == [{'q': '"example.com"', 'num': '3', 'page': '1', 'speed': 'fast'}]
    assert len(search.results) == 3
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_specstream_parses_new_evidence_from_a_repeated_link(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
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

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)
    report = await search.process()

    assert search.results == [{'title': 'Team', 'snippet': 'mail.example.com', 'url': page}]
    assert search.totalresults.count('\n') == 2
    assert 'ops@example.com' in await search.get_emails()
    assert {'mail.example.com', 'vpn.example.com'} <= set(await search.get_hostnames())
    assert report is None


pytestmark = pytest.mark.provider_contract('specstream')
