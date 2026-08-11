import logging
from typing import Any

import pytest

from theHarvester.discovery import chaos
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_http_failure_is_reported_without_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://dns.projectdiscovery.io/dns/example.com/subdomains']
        assert kwargs['headers']['Authorization'] == 'Bearer test-key'
        assert isinstance(kwargs['headers']['User-agent'], str)
        assert {key: value for key, value in kwargs.items() if key != 'headers'} == {
            'proxy': False,
            'json': True,
            'include_metadata': True,
        }
        return [FetcherResponse(body={'error': 'forbidden'}, status=403, headers={})]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'access-denied'
    assert 'Chaos request failed with HTTP 403' in caplog.text


@pytest.mark.asyncio
async def test_http_429_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'too many requests'}, status=429, headers={})]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'rate-limited'
    assert search.stop_reason == 'http-429'


@pytest.mark.parametrize('key', ['', '   '])
def test_empty_api_key_is_rejected(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: key)

    with pytest.raises(MissingKey):
        chaos.SearchChaos('example.com')


@pytest.mark.asyncio
async def test_provider_unauthorized_payload_is_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'unauthorized'}, status=200, headers={})]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'access-denied'


@pytest.mark.asyncio
async def test_malformed_response_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=7, status=200, headers={})]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'
    assert 'Chaos returned malformed data' in caplog.text


@pytest.mark.asyncio
async def test_success_preserves_supported_subdomain_shapes(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={'subdomains': ['api', {'name': 'WWW'}, {'name': 7}, {'unexpected': 'value'}]},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'
    assert caplog.text.count('Chaos ignored a malformed subdomain item') == 2


@pytest.mark.asyncio
async def test_malformed_subdomain_collection_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'subdomains': 7}, status=200, headers={})]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'
    assert 'Chaos returned malformed subdomain data' in caplog.text


@pytest.mark.asyncio
async def test_fetch_exception_is_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise OSError('private transport details')

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'
    assert 'private transport details' not in caplog.text


@pytest.mark.asyncio
async def test_parser_exception_preserves_valid_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    class ExplodingSubdomains(list[str]):
        def __iter__(self):
            yield 'api'
            raise ValueError('private provider payload')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={'subdomains': ExplodingSubdomains(['api'])},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = chaos.SearchChaos('example.com')

    with caplog.at_level(logging.INFO, logger=chaos.__name__):
        await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'
    assert 'private provider payload' not in caplog.text
