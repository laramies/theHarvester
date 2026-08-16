import asyncio
import logging
from typing import Any

import pytest

from theHarvester.discovery import fullhuntsearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_http_failure_is_reported_without_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')
    requests: list[str] = []

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        requests.extend(urls)
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'error': 'forbidden'}, status=403, headers={})]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    with caplog.at_level(logging.INFO, logger=fullhuntsearch.__name__):
        await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_ips() == []
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'access-denied'


@pytest.mark.parametrize('key', ['', '   '])
def test_empty_api_key_is_rejected(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: key)

    with pytest.raises(MissingKey):
        fullhuntsearch.SearchFullHunt('example.com')


def test_missing_api_key_configuration_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_key() -> str:
        raise KeyError('fullhunt')

    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', missing_key)

    with pytest.raises(MissingKey):
        fullhuntsearch.SearchFullHunt('example.com')


@pytest.mark.asyncio
async def test_malformed_domain_details_are_reported_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')
    requests: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requests.extend(urls)
        return [FetcherResponse(body={'unexpected': []}, status=200, headers={})]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    with caplog.at_level(logging.INFO, logger=fullhuntsearch.__name__):
        await search.process()

    assert await search.get_hostnames() == []
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_malformed_host_does_not_hide_later_valid_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'hosts': [
                        'not-an-object',
                        {'host': 7},
                        {'host': 'ports.example.com', 'network_ports': [{}]},
                        {'host': 'products.example.com', 'products': [{}]},
                        {'host': 'api.example.com', 'ip_address': '192.0.2.20'},
                    ]
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    with caplog.at_level(logging.INFO, logger=fullhuntsearch.__name__):
        await search.process()

    assert await search.get_hostnames() == ['api.example.com']
    assert await search.get_ips() == ['192.0.2.20']
    assert caplog.text.count('FullHunt ignored a malformed host item') == 4
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_malformed_subdomain_fallback_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')
    responses = [
        FetcherResponse(body={'hosts': []}, status=200, headers={}),
        FetcherResponse(body={'hosts': 7}, status=200, headers={}),
    ]

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    with caplog.at_level(logging.INFO, logger=fullhuntsearch.__name__):
        await search.process()

    assert await search.get_hostnames() == []
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_fallback_ignores_malformed_and_out_of_scope_hosts(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')
    responses = [
        FetcherResponse(body={'hosts': []}, status=200, headers={}),
        FetcherResponse(body={'hosts': [7, 'outside.test', 'API.Example.COM']}, status=200, headers={}),
    ]

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    with caplog.at_level(logging.INFO, logger=fullhuntsearch.__name__):
        await search.process()

    assert await search.get_hostnames() == ['api.example.com']
    assert caplog.text.count('FullHunt ignored a malformed subdomain item') == 2
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_nested_results_use_normalized_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'hosts': [
                        {
                            'host': 'API.Example.COM',
                            'dns_records': {'a': ['192.0.2.20']},
                            'http_response': {'status': 200},
                            'geo': {'country': 'US'},
                            'cloud': {'provider': 'example'},
                            'certificate': {'issuer': 'Example CA'},
                        }
                    ]
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')

    await search.process()

    assert await search.get_dns_records() == {'api.example.com': {'a': ['192.0.2.20']}}
    assert await search.get_http_info() == {'api.example.com': {'status': 200}}
    assert await search.get_geo_info() == {'api.example.com': {'country': 'US'}}
    assert await search.get_cloud_info() == {'api.example.com': {'provider': 'example'}}
    assert await search.get_certificate_info() == [{'issuer': 'Example CA', 'hostname': 'api.example.com'}]
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fullhuntsearch.SearchFullHunt('example.com')
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    with pytest.raises(asyncio.CancelledError):
        await fullhuntsearch.SearchFullHunt('example.com').process()


pytestmark = pytest.mark.provider_contract('fullhunt')
