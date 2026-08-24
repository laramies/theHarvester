import asyncio
from typing import Any

import pytest

from theHarvester.discovery import subdomainapi
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
async def test_process_keeps_every_returned_scoped_name_and_reports_the_provider_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        captured.update({'urls': urls, **kwargs})
        return [
            FetcherResponse(
                body={
                    'domain': 'example.com',
                    'count': 6,
                    'total': 10_006,
                    'subdomains': [
                        'API.Example.COM.',
                        'api.example.com',
                        'deep.api.example.com',
                        '*.wild.example.com',
                        'example.com',
                        'outside.test',
                    ],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(subdomainapi.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomainapi.SearchSubdomainApi('example.com')

    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'deep.api.example.com'}
    assert report == SourceExecutionReport('partial', 'provider-limit')
    assert captured == {
        'urls': ['https://api.subdomain.app/v1/query?domain=example.com'],
        'headers': {'User-Agent': subdomainapi.Core.get_user_agent()},
        'proxy': True,
        'json': True,
        'include_metadata': True,
    }


@pytest.mark.asyncio
async def test_process_accepts_a_valid_empty_response(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={'domain': 'example.com', 'count': 0, 'total': 0, 'subdomains': []},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(subdomainapi.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomainapi.SearchSubdomainApi('example.com')

    assert await search.process() is None
    assert await search.get_hostnames() == set()


@pytest.mark.parametrize(
    ('response', 'expected'),
    [
        (None, SourceExecutionReport('failed', 'transport-error')),
        (FetcherResponse({}, 403, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse({}, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse({}, 503, {}), SourceExecutionReport('failed', 'http-503')),
        (FetcherResponse([], 200, {}), SourceExecutionReport('failed', 'invalid-response')),
        (
            FetcherResponse(
                {'domain': 'example.com', 'count': 2, 'total': 2, 'subdomains': ['api.example.com']},
                200,
                {},
            ),
            SourceExecutionReport('failed', 'invalid-response'),
        ),
    ],
)
@pytest.mark.asyncio
async def test_process_reports_provider_and_response_failures(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    expected: SourceExecutionReport,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(subdomainapi.AsyncFetcher, 'fetch_all', fake_fetch_all)

    assert await subdomainapi.SearchSubdomainApi('example.com').process() == expected


@pytest.mark.asyncio
async def test_process_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancelled_fetch(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    monkeypatch.setattr(subdomainapi.AsyncFetcher, 'fetch_all', cancelled_fetch)

    with pytest.raises(asyncio.CancelledError):
        await subdomainapi.SearchSubdomainApi('example.com').process()


pytestmark = pytest.mark.provider_contract('subdomainapi')
