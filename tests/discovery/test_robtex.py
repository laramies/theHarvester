import logging
from typing import Any

import pytest

from theHarvester.discovery import robtex
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_robtex_does_not_send_domain_to_reverse_ip_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        return [
            FetcherResponse(
                body='{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}',
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert requested_urls == ['https://freeapi.robtex.com/pdns/forward/example.com']
    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [[], [''], ['not-json\n{}\n[]']])
async def test_robtex_handles_empty_or_malformed_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: list[str],
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={}) for payload in response]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_robtex_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[str]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', failed_fetch)
    search = robtex.SearchRobtex('example.com')

    with caplog.at_level(logging.INFO, logger=robtex.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'Robtex API error' in caplog.text


@pytest.mark.asyncio
async def test_robtex_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body='service unavailable', status=503, headers={})]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', failed_fetch)
    search = robtex.SearchRobtex('example.com')

    with caplog.at_level(logging.INFO, logger=robtex.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'Robtex request failed with HTTP 503' in caplog.text
