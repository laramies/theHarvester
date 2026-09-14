import contextlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import serplysearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


def _result(index: int) -> dict[str, str]:
    return {
        'title': f'Result {index}',
        'description': f'host-{index}.example.com',
        'link': f'https://host-{index}.example.com',
    }


def _response(results: list[dict[str, str]]) -> FetcherResponse:
    return FetcherResponse({'results': results}, 200, {})


def search_headers(search: serplysearch.SearchSerply) -> dict[str, str]:
    return {
        'Accept': 'application/json',
        'X-Api-Key': search.api_key,
    }


@pytest.fixture
def serply_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'serply': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_serply_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(serplysearch.asyncio, 'sleep', no_sleep)


def test_serply_requires_an_api_key() -> None:
    with pytest.raises(MissingKey, match='Serply'):
        serplysearch.SearchSerply('example.com', 10, credential_adapter=InMemoryCredentialAdapter({}))


def test_serply_treats_a_blank_key_as_missing() -> None:
    with pytest.raises(MissingKey, match='Serply'):
        serplysearch.SearchSerply(
            'example.com',
            10,
            credential_adapter=InMemoryCredentialAdapter({'serply': {'key': ''}}),
        )


@pytest.mark.asyncio
async def test_serply_normalizes_in_scope_evidence(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'title': 'Contact Admin@Example.COM.',
                        'description': 'Ignore outsider@example.net and api.example.net',
                        'link': 'https://Blog.Example.COM./contact',
                    }
                ]
            ),
            _response([]),
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

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    await search.process(proxy=True)

    assert session_options == [{'headers': search_headers(search), 'proxy': True, 'request_timeout': 60}]
    assert request_proxies == [None, None]
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_point', ['open', 'close'])
async def test_serply_reports_session_lifecycle_failures(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
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

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'open_session', failed_open_session)
    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_serply_does_not_misclassify_value_errors_as_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    @contextlib.asynccontextmanager
    async def failed_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        raise ValueError('programming defect')
        yield object()

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'open_session', failed_open_session)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    with pytest.raises(ValueError, match='programming defect'):
        await search.process()


@pytest.mark.parametrize('body', [None, []], ids=['empty', 'malformed'])
@pytest.mark.asyncio
async def test_serply_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
    body: list[Any] | None,
) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

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
async def test_serply_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
    response: FetcherResponse,
    expected_report: SourceExecutionReport,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response

    async def legacy_fetch(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('Serply must use the bounded fetch_json seam')

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch', legacy_fetch)

    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == expected_report


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_serply_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_serply_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise serplysearch.asyncio.CancelledError

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    with pytest.raises(serplysearch.asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        {},
        {'results': 'invalid'},
        {'results': ['invalid']},
    ],
)
async def test_serply_reports_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
    body: dict[str, Any],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
async def test_serply_reports_a_refusal_detail_as_a_provider_error(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    """Serply answers a refused request with a detail string instead of organic rows."""

    requests: list[str] = []

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        requests.append(kwargs.get('url', _args[0] if _args else ''))
        return FetcherResponse({'detail': 'Insufficient credits'}, 200, {})

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'provider-error')
    assert len(requests) == 1
    assert search.totalresults == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['title', 'description', 'link'])
async def test_serply_rejects_non_string_evidence_fields(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
    field: str,
) -> None:
    result: dict[str, object] = _result(1)
    result[field] = {'unexpected': 'host.example.com'}

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({'results': [result]}, 200, {})

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)

    assert await search.process() == SourceExecutionReport('failed', 'invalid-response')
    assert search.totalresults == ''


@pytest.mark.asyncio
async def test_serply_paginates_with_start_offsets_and_one_global_limit(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    """Serply ignores page and offset, so the window has to advance through start."""

    responses = iter(
        [
            _response([_result(index) for index in range(10)]),
            _response([_result(index) for index in range(10, 20)]),
            _response([_result(index) for index in range(20, 30)]),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 25, credential_adapter=serply_credentials)
    report = await search.process()

    assert requests == [
        {'q': ['"example.com"'], 'num': ['10'], 'start': ['0']},
        {'q': ['"example.com"'], 'num': ['10'], 'start': ['10']},
        {'q': ['"example.com"'], 'num': ['5'], 'start': ['20']},
    ]
    assert len(search.results) == 25
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_serply_stops_a_query_once_a_page_repeats_the_previous_window(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    """A provider that runs out of rows replays the last window rather than emptying it."""

    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(10)])

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', None, credential_adapter=serply_credentials)
    report = await search.process()

    assert [(request['q'], request['start']) for request in requests] == [
        (['"example.com"'], ['0']),
        (['"example.com"'], ['10']),
        (['site:example.com'], ['0']),
        (['site:example.com'], ['10']),
    ]
    assert len(search.results) == 20
    assert report is None


@pytest.mark.asyncio
async def test_serply_stops_a_query_on_a_short_page(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter([_response([_result(1)]), _response([_result(2)])])
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return next(responses, _response([]))

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)
    await search.process()

    assert [(request['q'], request['start'], request['num']) for request in requests] == [
        (['"example.com"'], ['0'], ['10']),
        (['site:example.com'], ['0'], ['9']),
    ]


@pytest.mark.asyncio
async def test_serply_trims_surplus_rows_because_num_is_an_approximate_cap(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(10)])

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 3, credential_adapter=serply_credentials)
    report = await search.process()

    assert [request['num'] for request in requests] == [['3']]
    assert len(search.results) == 3
    assert report == SourceExecutionReport('completed', 'result-limit')


@pytest.mark.asyncio
async def test_serply_reports_the_page_boundary_as_truncation_when_unlimited(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        page = len(requests)
        return _response([_result(page * 10 + index) for index in range(10)])

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', None, credential_adapter=serply_credentials)
    report = await search.process()

    assert [request['start'] for request in requests] == [[str(page * 10)] for page in range(10)]
    assert report == SourceExecutionReport('partial', 'provider-limit')


@pytest.mark.asyncio
async def test_serply_stops_after_an_exact_full_page(
    monkeypatch: pytest.MonkeyPatch,
    serply_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> FetcherResponse:
        url = kwargs.get('url', _args[0] if _args else '')
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(10)])

    monkeypatch.setattr(serplysearch.AsyncFetcher, 'fetch_json', fake_fetch)
    search = serplysearch.SearchSerply('example.com', 10, credential_adapter=serply_credentials)
    report = await search.process()

    assert [(request['start'], request['num']) for request in requests] == [(['0'], ['10'])]
    assert report == SourceExecutionReport('completed', 'result-limit')


pytestmark = pytest.mark.provider_contract('serply')
