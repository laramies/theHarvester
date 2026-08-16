from typing import Any

import pytest

from theHarvester.discovery import search_dnsdumpster
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_keeps_only_label_scoped_records_and_preserves_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search_dnsdumpster.Core, 'dnsdumpster_key', staticmethod(lambda: 'test-key'))
    captured: dict[str, Any] = {}

    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        captured.update(kwargs)
        return [
            FetcherResponse(
                body={
                    'a': [
                        {'host': 'API.Example.COM.', 'ips': [{'ip': '192.0.2.10'}]},
                        {'host': 'notexample.com', 'ips': [{'ip': '198.51.100.20'}]},
                    ],
                    'ns': [],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(search_dnsdumpster.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = search_dnsdumpster.SearchDNSDumpster('example.com')

    report = await search.process(proxy=True)

    assert captured['proxy'] is True
    assert captured['include_metadata'] is True
    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.10'}
    assert report is None


@pytest.mark.asyncio
async def test_valid_empty_response_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search_dnsdumpster.Core, 'dnsdumpster_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'a': [], 'ns': []}, status=200, headers={})]

    monkeypatch.setattr(search_dnsdumpster.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = search_dnsdumpster.SearchDNSDumpster('example.com')

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert report is None


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body=[], status=200, headers={}), 'failed', 'invalid-response'),
        (FetcherResponse(body={}, status=200, headers={}), 'failed', 'invalid-response'),
        (FetcherResponse(body={'error': 'private provider detail'}, status=200, headers={}), 'failed', 'provider-error'),
        (FetcherResponse(body={'a': {}, 'ns': []}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failed_responses_are_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(search_dnsdumpster.Core, 'dnsdumpster_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(search_dnsdumpster.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = search_dnsdumpster.SearchDNSDumpster('example.com')

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert report.status == execution_status
    assert report.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_valid_and_malformed_records_preserve_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search_dnsdumpster.Core, 'dnsdumpster_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'a': [
                        {'host': 'api.example.com', 'ips': [{'ip': '2001:0db8::1'}, {'ip': None}]},
                        {'host': 7, 'ips': [{'ip': '192.0.2.9'}]},
                        'malformed-record',
                    ],
                    'ns': [],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(search_dnsdumpster.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = search_dnsdumpster.SearchDNSDumpster('example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'2001:db8::1'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_fetch_exception_is_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search_dnsdumpster.Core, 'dnsdumpster_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise OSError('offline transport failure')

    monkeypatch.setattr(search_dnsdumpster.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = search_dnsdumpster.SearchDNSDumpster('example.com')

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'transport-error'


pytestmark = pytest.mark.provider_contract('dnsdumpster')
