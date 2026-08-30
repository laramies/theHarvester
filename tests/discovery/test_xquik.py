import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import xquik
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def response(body: object, status: int = 200, headers: dict[str, str] | None = None) -> FetcherResponse:
    return FetcherResponse(body, status, headers or {})


@pytest.fixture(autouse=True)
def configured_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xquik.Core, 'xquik_key', staticmethod(lambda: ' test-key '))


@pytest.fixture
def provider_session(monkeypatch: pytest.MonkeyPatch) -> tuple[object, list[dict[str, Any]], list[bool]]:
    session = object()
    options: list[dict[str, Any]] = []
    exits: list[bool] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        options.append(kwargs)
        try:
            yield session
        finally:
            exits.append(True)

    monkeypatch.setattr(xquik.AsyncFetcher, 'open_session', fake_open_session)
    return session, options, exits


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(xquik.Core, 'xquik_key', staticmethod(lambda: key))

    with pytest.raises(MissingKey):
        xquik.SearchXquik('example.com', 10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_a_positive_integer(limit: Any) -> None:
    with pytest.raises(ValueError, match='positive integer'):
        xquik.SearchXquik('example.com', limit)


@pytest.mark.asyncio
async def test_process_paginates_in_one_session_and_returns_canonical_urls(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    session, session_options, session_exits = provider_session
    responses = [
        response(
            {
                'tweets': [{'id': '100'}, {'id': '200'}, {'id': '100'}],
                'has_next_page': True,
                'next_cursor': 'page-2',
            }
        ),
        response({'tweets': [{'id': '200'}, {'id': '300'}], 'has_next_page': False, 'next_cursor': ''}),
    ]
    calls: list[dict[str, Any]] = []

    async def fake_fetch_json(*args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append({'args': args, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process(proxy=True)

    assert report is None
    assert await search.get_urls() == {
        'https://x.com/i/web/status/100',
        'https://x.com/i/web/status/200',
        'https://x.com/i/web/status/300',
    }
    assert session_options == [
        {
            'headers': {'Accept': 'application/json', 'x-api-key': 'test-key'},
            'proxy': True,
            'request_timeout': 60,
        }
    ]
    assert session_exits == [True]
    assert calls == [
        {
            'args': (search.SEARCH_URL,),
            'session': session,
            'params': {'q': 'example.com', 'queryType': 'Latest', 'limit': 10},
            'request_timeout': 60,
        },
        {
            'args': (search.SEARCH_URL,),
            'session': session,
            'params': {'q': 'example.com', 'queryType': 'Latest', 'limit': 10, 'cursor': 'page-2'},
            'request_timeout': 60,
        },
    ]
    assert responses == []


@pytest.mark.asyncio
async def test_result_limit_stops_without_requiring_another_cursor(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    calls = 0

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return response({'tweets': [{'id': '1'}, {'id': '2'}, {'id': '3'}], 'has_next_page': True})

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 2)

    report = await search.process()

    assert report == SourceExecutionReport('completed', 'result-limit')
    assert await search.get_urls() == {'https://x.com/i/web/status/1', 'https://x.com/i/web/status/2'}
    assert calls == 1


@pytest.mark.asyncio
async def test_unlimited_search_uses_a_bounded_page_size(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    calls: list[dict[str, int | str]] = []

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['params'])
        return response({'tweets': [], 'has_next_page': False})

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await xquik.SearchXquik('example.com', None).process()

    assert report is None
    assert calls == [{'q': 'example.com', 'queryType': 'Latest', 'limit': 500}]


@pytest.mark.parametrize(
    ('body', 'expected_status'),
    [
        ([], 'failed'),
        ({}, 'failed'),
        ({'tweets': {}, 'has_next_page': False}, 'failed'),
        ({'tweets': [], 'has_next_page': 'false'}, 'failed'),
        ({'tweets': [], 'has_next_page': True, 'next_cursor': ''}, 'failed'),
        ({'tweets': [], 'has_next_page': True, 'next_cursor': '\n'}, 'failed'),
        ({'tweets': [], 'has_next_page': True, 'next_cursor': 'a' * 8193}, 'failed'),
    ],
)
@pytest.mark.asyncio
async def test_malformed_responses_fail_without_evidence(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
    body: object,
    expected_status: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response(body)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report.status == expected_status
    assert report.stop_reason == 'invalid-response'
    assert await search.get_urls() == set()


@pytest.mark.asyncio
async def test_malformed_tweet_keeps_valid_evidence_and_marks_partial(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    payload = {
        'tweets': [
            {'id': '100'},
            {'id': '../private'},
            {'id': 200},
            {'id': '１２３'},
            {'id': '1' * 33},
            'not-an-object',
            {'id': '300'},
        ],
        'has_next_page': False,
    }

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response(payload)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'invalid-response')
    assert await search.get_urls() == {
        'https://x.com/i/web/status/100',
        'https://x.com/i/web/status/300',
    }


@pytest.mark.asyncio
async def test_malformed_page_cannot_report_a_clean_result_limit(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response({'tweets': [{'id': '100'}, {'id': 'invalid'}], 'has_next_page': True})

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 1)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'invalid-response')
    assert await search.get_urls() == {'https://x.com/i/web/status/100'}


@pytest.mark.asyncio
async def test_repeated_cursor_preserves_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'same'}),
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'same'}),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'repeated-cursor')
    assert await search.get_urls() == {'https://x.com/i/web/status/100'}
    assert responses == []


@pytest.mark.asyncio
async def test_repeated_cursor_without_evidence_fails(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [], 'has_next_page': True, 'next_cursor': 'same'}),
        response({'tweets': [], 'has_next_page': True, 'next_cursor': 'same'}),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await xquik.SearchXquik('example.com', 10).process()

    assert report == SourceExecutionReport('failed', 'repeated-cursor')
    assert responses == []


@pytest.mark.parametrize(
    ('responses', 'expected_report', 'expected_sleeps'),
    [
        ([response(None, 401)], SourceExecutionReport('failed', 'access-denied'), []),
        ([response(None, 402)], SourceExecutionReport('failed', 'http-402'), []),
        ([response(None, 409)], SourceExecutionReport('failed', 'cursor-busy'), []),
        (
            [response(None, 429, {'retry-after': '2'}), response(None, 429, {'retry-after': '2'})],
            SourceExecutionReport('rate-limited', 'http-429'),
            [2],
        ),
        (
            [response(None, 503, {'retry-after': 'invalid'}), response(None, 503)],
            SourceExecutionReport('failed', 'http-503'),
            [1],
        ),
        (
            [response(None, 424, {'retry-after': '1000'}), response(None, 424)],
            SourceExecutionReport('failed', 'http-424'),
            [60],
        ),
        (
            [response(None, 502), response(None, 502)],
            SourceExecutionReport('failed', 'http-502'),
            [1],
        ),
    ],
)
@pytest.mark.asyncio
async def test_http_failures_and_bounded_retries_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
    responses: list[FetcherResponse],
    expected_report: SourceExecutionReport,
    expected_sleeps: list[int],
) -> None:
    sleeps: list[int] = []

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    async def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(xquik.asyncio, 'sleep', fake_sleep)

    report = await xquik.SearchXquik('example.com', 10).process()

    assert report == expected_report
    assert sleeps == expected_sleeps
    assert responses == []


@pytest.mark.asyncio
async def test_busy_cursor_retries_once_with_the_same_identity(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'page-2'}),
        response(None, 409, {'retry-after': '3'}),
        response({'tweets': [{'id': '200'}], 'has_next_page': False}),
    ]
    calls: list[dict[str, int | str]] = []
    sleeps: list[int] = []

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['params'])
        return responses.pop(0)

    async def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(xquik.asyncio, 'sleep', fake_sleep)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report is None
    assert calls[1:] == [
        {'q': 'example.com', 'queryType': 'Latest', 'limit': 10, 'cursor': 'page-2'},
        {'q': 'example.com', 'queryType': 'Latest', 'limit': 10, 'cursor': 'page-2'},
    ]
    assert sleeps == [3]
    assert await search.get_urls() == {
        'https://x.com/i/web/status/100',
        'https://x.com/i/web/status/200',
    }


@pytest.mark.asyncio
async def test_busy_cursor_stops_after_one_retry(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'page-2'}),
        response(None, 409, {'retry-after': '0'}),
        response(None, 409),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    async def fake_sleep(_seconds: int) -> None:
        return None

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(xquik.asyncio, 'sleep', fake_sleep)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'cursor-busy')
    assert await search.get_urls() == {'https://x.com/i/web/status/100'}
    assert responses == []


@pytest.mark.asyncio
async def test_expired_cursor_restarts_once_and_deduplicates_results(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'old'}),
        response(None, 410),
        response({'tweets': [{'id': '100'}, {'id': '200'}], 'has_next_page': False}),
    ]
    calls: list[dict[str, int | str]] = []

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        calls.append(kwargs['params'])
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report is None
    assert calls == [
        {'q': 'example.com', 'queryType': 'Latest', 'limit': 10},
        {'q': 'example.com', 'queryType': 'Latest', 'limit': 10, 'cursor': 'old'},
        {'q': 'example.com', 'queryType': 'Latest', 'limit': 10},
    ]
    assert await search.get_urls() == {
        'https://x.com/i/web/status/100',
        'https://x.com/i/web/status/200',
    }
    assert responses == []


@pytest.mark.asyncio
async def test_invalid_cursor_restarts_once_and_deduplicates_results(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'bad'}),
        response(None, 400),
        response({'tweets': [{'id': '100'}, {'id': '200'}], 'has_next_page': False}),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report is None
    assert await search.get_urls() == {
        'https://x.com/i/web/status/100',
        'https://x.com/i/web/status/200',
    }
    assert responses == []


@pytest.mark.asyncio
async def test_second_expired_cursor_reports_partial_coverage(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'old'}),
        response(None, 410),
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'new'}),
        response(None, 410),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'cursor-expired')
    assert await search.get_urls() == {'https://x.com/i/web/status/100'}
    assert responses == []


@pytest.mark.asyncio
async def test_second_invalid_cursor_reports_partial_coverage(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    responses = [
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'old'}),
        response(None, 400),
        response({'tweets': [{'id': '100'}], 'has_next_page': True, 'next_cursor': 'new'}),
        response(None, 400),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = xquik.SearchXquik('example.com', 10)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'invalid-cursor')
    assert await search.get_urls() == {'https://x.com/i/web/status/100'}
    assert responses == []


@pytest.mark.parametrize('reason', ['invalid-response', 'response-limit', 'transport-error'])
@pytest.mark.asyncio
async def test_bounded_fetch_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await xquik.SearchXquik('example.com', 10).process()

    assert report == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_unexpected_transport_failure_is_structured(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise RuntimeError('provider-private-detail')

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await xquik.SearchXquik('example.com', 10).process()

    assert report == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_cancellation_closes_the_provider_session(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: tuple[object, list[dict[str, Any]], list[bool]],
) -> None:
    _session, _options, exits = provider_session

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(xquik.AsyncFetcher, 'fetch_json', fake_fetch_json)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await xquik.SearchXquik('example.com', 10).process()
    assert exits == [True]


pytestmark = pytest.mark.provider_contract('xquik')
