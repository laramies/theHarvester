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
    assert 'Chaos request failed with HTTP 403' in caplog.text


@pytest.mark.parametrize('key', ['', '   '])
def test_empty_api_key_is_rejected(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: key)

    with pytest.raises(MissingKey):
        chaos.SearchChaos('example.com')


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
    assert 'Chaos returned malformed subdomain data' in caplog.text
