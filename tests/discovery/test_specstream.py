import contextlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from theHarvester.discovery import specstreamsearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


def _source(index: int) -> dict[str, Any]:
    return {
        'url': f'https://host-{index}.example.com',
        'title': f'Result {index}',
        'site': f'host-{index}.example.com',
        'snippet': f'host-{index}.example.com',
        'cited': False,
        'published': None,
    }


def _response(sources: list[dict[str, Any]], next_page: int | None = None) -> FetcherResponse:
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
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(specstreamsearch.asyncio, 'sleep', no_sleep)


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
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

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
async def test_specstream_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
    field: str,
) -> None:
    source: dict[str, object] = _source(1)
    source[field] = {'unexpected': 'host.example.com'}

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'data': {'sources': [source], 'next_page': None}}, 200, {})

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
async def test_specstream_tolerates_missing_title_and_snippet(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([{'url': 'https://www.example.com/', 'title': None}, {'title': 'no url'}])

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', 10, credential_adapter=specstream_credentials)

    assert await search.process() is None
    assert search.results == [{'title': '', 'snippet': '', 'url': 'https://www.example.com/'}]
    assert await search.get_hostnames() == ['www.example.com']


@pytest.mark.asyncio
async def test_specstream_follows_next_page_with_a_fixed_page_size(
    monkeypatch: pytest.MonkeyPatch,
    specstream_credentials: InMemoryCredentialAdapter,
) -> None:
    """Page two is requested only because page one named it, with the same num and a Bearer key."""

    responses = iter(
        [
            _response([_source(index) for index in range(10)], next_page=2),
            _response([_source(index) for index in range(10, 14)]),
            _response([_source(index) for index in range(20, 23)]),
        ]
    )
    requests: list[tuple[str, dict[str, str], dict[str, str]]] = []

    async def fake_fetch_json(url: str, **kwargs: Any) -> FetcherResponse:
        base = url.split('?', 1)[0]
        requests.append((base, _params(url), kwargs['headers']))
        return next(responses)

    monkeypatch.setattr(specstreamsearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = specstreamsearch.SearchSpecstream('example.com', None, credential_adapter=specstream_credentials)
    report = await search.process()

    server = 'https://api.specstream.ai/v1/web-search'
    assert [(base, params) for base, params, _headers in requests] == [
        (server, {'q': '"example.com"', 'num': '10', 'page': '1', 'speed': 'fast'}),
        (server, {'q': '"example.com"', 'num': '10', 'page': '2', 'speed': 'fast'}),
        (server, {'q': 'site:example.com', 'num': '10', 'page': '1', 'speed': 'fast'}),
    ]
    assert all(headers['Authorization'] == 'Bearer test-token' for _base, _params_, headers in requests)
    assert len(search.results) == 17
    assert report is None


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
