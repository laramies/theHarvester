import contextlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import bravesearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


def _result(index: int) -> dict[str, str]:
    return {
        'title': f'Result {index}',
        'description': f'host-{index}.example.com',
        'url': f'https://host-{index}.example.com',
    }


def _response(results: list[dict[str, str]], *, more: bool) -> FetcherResponse:
    return FetcherResponse(
        {
            'query': {'more_results_available': more},
            'web': {'results': results},
        },
        200,
        {},
    )


@pytest.fixture
def brave_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'brave': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_brave_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(bravesearch.asyncio, 'sleep', no_sleep)


def test_brave_requires_an_api_key() -> None:
    with pytest.raises(MissingKey, match='Brave Search'):
        bravesearch.SearchBrave('example.com', 10, credential_adapter=InMemoryCredentialAdapter({}))


@pytest.mark.asyncio
async def test_brave_normalizes_in_scope_evidence(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'title': 'Contact Admin@Example.COM.',
                        'description': 'Ignore outsider@example.net and api.example.net',
                        'url': 'https://Blog.Example.COM./contact',
                    }
                ],
                more=False,
            ),
            FetcherResponse({'error': {'message': 'Access denied', 'code': 'forbidden'}}, 200, {}),
        ]
    )

    request_proxies: list[bool | None] = []
    session_options: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        session_options.append(kwargs)
        yield object()

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        request_proxies.append(kwargs.get('proxy'))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    await search.process(proxy=True)

    assert session_options == [{'headers': search_headers(search), 'proxy': True, 'request_timeout': 60}]
    assert request_proxies == [None, None]
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


def search_headers(search: bravesearch.SearchBrave) -> dict[str, str]:
    return {
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip',
        'X-Subscription-Token': search.api_key,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_point', ['open', 'close'])
async def test_brave_reports_session_lifecycle_failures(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    failure_point: str,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        if failure_point == 'open':
            raise OSError('session creation failed')
        yield object()
        raise OSError('session close failed')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([], more=False)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'open_session', failed_open_session)
    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_brave_does_not_misclassify_value_errors_as_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        raise ValueError('programming defect')
        yield object()

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'open_session', failed_open_session)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    with pytest.raises(ValueError, match='programming defect'):
        await search.process()


@pytest.mark.parametrize('body', [None, []], ids=['empty', 'malformed'])
@pytest.mark.asyncio
async def test_brave_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    body: list[Any] | None,
) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    report = await search.process()

    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []
    assert report == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_report'),
    [
        (FetcherResponse(None, 401, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse(None, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse(None, 503, {}), SourceExecutionReport('failed', 'http-503')),
    ],
)
async def test_brave_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    response: FetcherResponse,
    expected_report: SourceExecutionReport,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response

    async def legacy_fetch(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('Brave must use the bounded fetch_json seam')

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', legacy_fetch)

    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    assert await search.process() == expected_report


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_brave_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    assert await search.process() == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_brave_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise bravesearch.asyncio.CancelledError

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    with pytest.raises(bravesearch.asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        {},
        {'web': []},
        {'web': {'results': 'invalid'}, 'query': {'more_results_available': False}},
        {'web': {'results': []}, 'query': {}},
        {'web': {'results': ['invalid']}, 'query': {'more_results_available': False}},
    ],
)
async def test_brave_reports_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    body: dict[str, Any],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['title', 'description', 'url'])
async def test_brave_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
    field: str,
) -> None:
    result: dict[str, object] = _result(1)
    result[field] = {'unexpected': 'host.example.com'}

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(
            {'web': {'results': [result]}, 'query': {'more_results_available': False}},
            200,
            {},
        )

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
async def test_brave_uses_page_offsets_and_one_global_limit(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(index) for index in range(20)], more=True),
            _response([_result(index) for index in range(20, 30)], more=True),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 25, credential_adapter=brave_credentials)
    await search.process()

    assert requests == [
        {
            'q': ['"example.com"'],
            'count': ['20'],
            'offset': ['0'],
            'safesearch': ['off'],
            'freshness': ['all'],
            'extra_snippets': ['true'],
            'text_decorations': ['true'],
            'spellcheck': ['true'],
        },
        {
            'q': ['"example.com"'],
            'count': ['5'],
            'offset': ['1'],
            'safesearch': ['off'],
            'freshness': ['all'],
            'extra_snippets': ['true'],
            'text_decorations': ['true'],
            'spellcheck': ['true'],
        },
    ]
    assert len(search.results) == 25


@pytest.mark.asyncio
async def test_brave_requests_another_page_only_when_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(1)], more=False),
            _response([_result(2)], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses, _response([], more=False))

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)
    await search.process()

    assert [(request['q'], request['offset'], request['count']) for request in requests] == [
        (['"example.com"'], ['0'], ['10']),
        (['site:example.com'], ['0'], ['9']),
    ]


@pytest.mark.asyncio
async def test_brave_continues_sparse_pages_while_more_results_are_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(1)], more=True),
            _response([_result(index) for index in range(2, 21)], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials)
    await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [
        (['0'], ['20']),
        (['1'], ['19']),
    ]
    assert len(search.results) == 20


@pytest.mark.asyncio
async def test_brave_rejects_empty_page_that_claims_more_results(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return _response([], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials)

    report = await search.process()

    assert report == SourceExecutionReport('failed', 'invalid-response')
    assert search.results == []


@pytest.mark.asyncio
async def test_brave_stops_after_an_exact_full_page(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(20)], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials)
    report = await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [(['0'], ['20'])]
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_brave_rate_limit_does_not_skip_to_the_next_page(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            FetcherResponse({'error': {'message': 'Rate limit exceeded', 'code': 'rate_limit_exceeded'}}, 200, {}),
            _response([], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 40, credential_adapter=brave_credentials)
    report = await search.process()

    assert [(request['q'], request['offset']) for request in requests] == [(['"example.com"'], ['0'])]
    assert report == SourceExecutionReport('rate-limited', 'provider-rate-limit')


@pytest.mark.asyncio
async def test_brave_reports_provider_offset_boundary_as_truncation_when_unlimited(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(len(requests))], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = bravesearch.SearchBrave('example.com', None, credential_adapter=brave_credentials)
    report = await search.process()

    assert [request['offset'] for request in requests] == [[str(offset)] for offset in range(10)]
    assert report == SourceExecutionReport('partial', 'provider-limit')


pytestmark = pytest.mark.provider_contract('brave')
