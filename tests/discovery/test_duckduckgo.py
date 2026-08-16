import asyncio
import json
from typing import Any

import pytest

from theHarvester.discovery import duckduckgosearch
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_report'),
    [
        (FetcherResponse(None, 401, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse(None, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse(None, 503, {}), SourceExecutionReport('failed', 'http-503')),
    ],
)
async def test_duckduckgo_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse,
    expected_report: SourceExecutionReport,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return response

    async def legacy_fetch_all(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('DuckDuckGo must use the bounded fetch_json seam')

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_all', legacy_fetch_all)

    search = duckduckgosearch.SearchDuckDuckGo('example.com', 100)

    assert await search.process() == expected_report


@pytest.mark.asyncio
async def test_duckduckgo_does_not_fetch_provider_returned_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, bool]] = []
    payload = """
    {
      "AbstractURL": "https://api.example.com",
      "AbstractText": "Contact admin@example.com.",
      "Results": [{"FirstURL": "https://outside.test"}]
    }
    """

    async def fake_fetch_json(
        url: str,
        *,
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> FetcherResponse:
        requests.append((url, proxy))
        return FetcherResponse(json.loads(payload), 200, {})

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = duckduckgosearch.SearchDuckDuckGo('example.com', 100)
    await search.process(proxy=True)

    assert requests == [('https://api.duckduckgo.com/?q=example.com&format=json&pretty=1', True)]
    assert await search.get_hostnames() == ['api.example.com', 'example.com']
    assert await search.get_emails() == {'admin@example.com'}


@pytest.mark.parametrize(
    'payload',
    [
        '',
        '{"broken": ',
        '{"error": "Access denied", "url": "https://api.example.net"}',
        '{"unexpected": "host.example.com"}',
        '{"AbstractText": {"unexpected": "host.example.com"}}',
        '{"Results": [{"FirstURL": {"unexpected": "host.example.com"}}]}',
    ],
    ids=['empty', 'malformed', 'blocked', 'unknown-schema', 'invalid-text-field', 'invalid-result-field'],
)
@pytest.mark.asyncio
async def test_duckduckgo_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        if payload == '{"broken": ':
            raise ResponseStreamError('invalid-response')
        return FetcherResponse(json.loads(payload) if payload else None, 200, {})

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = duckduckgosearch.SearchDuckDuckGo('example.com', 100)

    report = await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_emails() == set()
    assert report == SourceExecutionReport(
        'failed',
        'access-denied' if 'Access denied' in payload else 'invalid-response',
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_duckduckgo_reports_bounded_fetch_failures(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await duckduckgosearch.SearchDuckDuckGo('example.com', 100).process()

    assert report == SourceExecutionReport('failed', reason)


@pytest.mark.asyncio
async def test_duckduckgo_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)

    with pytest.raises(asyncio.CancelledError):
        await duckduckgosearch.SearchDuckDuckGo('example.com', 100).process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('body', 'expected_report'),
    [
        ({}, None),
        ({'error': 'Rate limit exceeded'}, SourceExecutionReport('rate-limited', 'provider-rate-limit')),
        ({'error': 'Unknown provider failure'}, SourceExecutionReport('failed', 'provider-error')),
    ],
)
async def test_duckduckgo_classifies_valid_empty_and_provider_error_payloads(
    monkeypatch: pytest.MonkeyPatch,
    body: dict[str, str],
    expected_report: SourceExecutionReport | None,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body, 200, {})

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_json', fake_fetch_json)

    report = await duckduckgosearch.SearchDuckDuckGo('example.com', 100).process()

    assert report == expected_report


pytestmark = pytest.mark.provider_contract('duckduckgo')
