import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from theHarvester.discovery import shodan_internetdb
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_runner import SourceOutcome, SourceRequest, run_source


async def _run_with_response(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    response: FetcherResponse | None,
) -> SourceOutcome:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'hibpverified_key', lambda: 'test-key')
    monkeypatch.setattr(AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(shodan_internetdb, 'resolve_ip_addresses', AsyncMock(return_value=['192.0.2.1']))
    return await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified', 'hudsonrock', 'subdomaincenter', 'shodanInternetDB']
)
async def test_http_429_is_a_rate_limited_source_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body={}, status=429, headers={'retry-after': '0'}))

    assert outcome.execution.status == 'rate-limited'
    assert outcome.execution.stop_reason == 'http-429'
    assert outcome.execution.result_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified'])
async def test_http_401_is_an_access_denied_source_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body={}, status=401, headers={}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'access-denied')


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified'])
async def test_http_503_is_a_failed_source_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body={}, status=503, headers={}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'http-503')


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified'])
async def test_missing_response_is_a_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, None)

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'transport-error')


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified'])
async def test_transport_exception_is_a_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    source: str,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise OSError('private provider detail')

    monkeypatch.setattr(Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'hibpverified_key', lambda: 'test-key')
    monkeypatch.setattr(AsyncFetcher, 'fetch_all', failed_fetch)

    outcome = await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'transport-error')
    assert 'private provider detail' not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'body'),
    [('leakix', {}), ('rapiddns', ''), ('shodanct', {}), ('hibpverified', [])],
)
async def test_malformed_success_envelope_is_a_failed_source_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    body: object,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body=body, status=200, headers={}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'invalid-response')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'body'),
    [
        ('leakix', []),
        ('rapiddns', '<table><tbody></tbody></table>'),
        ('shodanct', []),
        ('hibpverified', {}),
    ],
)
async def test_valid_empty_response_completes_with_no_results(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    body: object,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body=body, status=200, headers={}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('completed', 'no-results')


@pytest.mark.asyncio
async def test_hibp_404_completes_with_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    outcome = await _run_with_response(
        monkeypatch,
        'hibpverified',
        FetcherResponse(body={}, status=404, headers={}),
    )

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('completed', 'no-results')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'body', 'value'),
    [
        ('subdomaincenter', ['api.example.test', 'api.example.test'], 'api.example.test'),
        ('hudsonrock', {'data': {'emails': ['user@example.test', 'user@example.test']}}, 'user@example.test'),
    ],
)
async def test_duplicate_records_remain_successful_evidence(monkeypatch, source, body, value):
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body, 200, {}))

    assert outcome.execution.status == 'completed'
    assert [observation.value for observation in outcome.observations] == [value]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('body', 'reason'),
    [({'error': 'provider unavailable'}, 'provider-error'), ({}, 'invalid-response')],
)
async def test_hudsonrock_rejects_incomplete_domain_envelopes(monkeypatch, body, reason):
    outcome = await _run_with_response(monkeypatch, 'hudsonrock', FetcherResponse(body, 200, {}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', reason)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'body', 'result_count'),
    [
        ('leakix', [{'subdomain': 'api.example.test'}, None], 1),
        (
            'rapiddns',
            '<table><tbody><tr><td>api.example.test</td><td>192.0.2.1</td><td>A</td></tr><tr><td></td></tr></tbody></table>',
            2,
        ),
        ('shodanct', ['api.example.test', None], 1),
        ('hibpverified', {'alice': ['ExampleBreach'], '': ['Malformed']}, 2),
    ],
)
async def test_parsing_failure_preserves_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    body: object,
    result_count: int,
) -> None:
    outcome = await _run_with_response(monkeypatch, source, FetcherResponse(body=body, status=200, headers={}))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('partial', 'invalid-response')
    assert outcome.execution.result_count == result_count


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['leakix', 'rapiddns', 'shodanct', 'hibpverified'])
async def test_cancellation_propagates_and_commits_cancelled_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    async def cancelled_fetch(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    committed = []
    monkeypatch.setattr(Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'hibpverified_key', lambda: 'test-key')
    monkeypatch.setattr(AsyncFetcher, 'fetch_all', cancelled_fetch)

    with pytest.raises(asyncio.CancelledError):
        await run_source(
            SourceRequest(source, 'example.test', 10, 0, False, True),
            commit_cancelled=committed.append,
        )

    assert len(committed) == 1
    assert (committed[0].execution.status, committed[0].execution.stop_reason) == ('failed', 'cancelled')
