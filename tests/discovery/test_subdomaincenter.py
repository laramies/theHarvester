import logging
from typing import Any

import pytest

from theHarvester.discovery import subdomaincenter
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_preserves_www_hostname(monkeypatch):
    async def fake_fetch_all(urls, **_kwargs):
        return [FetcherResponse(body=['www.example.com'], status=200, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all))
    search = subdomaincenter.SubdomainCenter('example.com')

    await search.process()

    assert await search.get_hostnames() == {'www.example.com'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('payload', 'expected'),
    [
        (None, set()),
        ({'unexpected': 'shape'}, set()),
        ('api.example.com', set()),
        (['api.example.com', None], {'api.example.com'}),
    ],
)
async def test_process_rejects_malformed_results(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
    expected: set[str],
) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://api.subdomain.center/?domain=example.com']
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomaincenter.SubdomainCenter('example.com')

    await search.process()

    assert await search.get_hostnames() == expected


@pytest.mark.asyncio
async def test_process_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', failed_fetch)
    search = subdomaincenter.SubdomainCenter('example.com')

    with caplog.at_level(logging.INFO, logger=subdomaincenter.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert 'SubdomainCenter' in caplog.text


@pytest.mark.asyncio
async def test_process_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body=[], status=429, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', failed_fetch)
    search = subdomaincenter.SubdomainCenter('example.com')

    with caplog.at_level(logging.INFO, logger=subdomaincenter.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert 'SubdomainCenter request failed with HTTP 429' in caplog.text
