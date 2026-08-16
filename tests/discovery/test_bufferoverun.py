from typing import Any

import pytest

from theHarvester.discovery import bufferoverun
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_parses_historical_four_column_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', staticmethod(lambda: 'test-key'))
    captured: dict[str, Any] = {}

    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        captured.update(kwargs)
        return [
            FetcherResponse(
                body={
                    'Results': [
                        '192.0.2.10,hash-1,"Example, Inc.",api.example.com',
                        '2001:db8::10,hash-2,Example Org,ipv6.example.com',
                        'malformed,row',
                    ]
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.process(proxy=True)

    assert captured['proxy'] is True
    assert await search.get_hostnames() == {'api.example.com', 'ipv6.example.com'}
    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'




@pytest.mark.asyncio
async def test_valid_empty_response_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'Results': []}, status=200, headers={})]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body={'Results': {}}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failed_responses_are_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_domain_first_five_column_row_is_rejected_without_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={'Results': ['sub.example.com,192.0.2.10,x,x,x']},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_non_string_row_preserves_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={'Results': ['192.0.2.10,hash,Example Org,api.example.com', None]},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


pytestmark = pytest.mark.provider_contract('bufferoverun')
