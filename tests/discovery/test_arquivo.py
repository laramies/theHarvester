import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import arquivo
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_collects_scoped_hosts_from_one_cdx_request(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        assert kwargs['include_metadata'] is True
        assert kwargs['headers']['User-agent']
        return [
            FetcherResponse(
                body='\n'.join(
                    (
                        '{"url": "https://API.Example.COM/path"}',
                        '{"url": "http://www.example.com/"}',
                        '{"url": "https://api.example.com/repeated"}',
                        '{"url": "https://example.com/"}',
                        '{"url": "https://outside.test/"}',
                        '{"url": 42}',
                        'not-json',
                    )
                ),
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = arquivo.SearchArquivo('Example.COM.', 750)
    await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert len(requested_urls) == 1
    assert parse_qs(urlparse(requested_urls[0]).query) == {
        'url': ['example.com'],
        'matchType': ['domain'],
        'output': ['json'],
        'fields': ['url'],
        'limit': ['750'],
    }


@pytest.mark.asyncio
async def test_process_bounds_the_provider_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        return [FetcherResponse(body='', status=200, headers={})]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = arquivo.SearchArquivo('example.com', 100_001)
    await search.process()

    assert parse_qs(urlparse(requested_urls[0]).query)['limit'] == ['10000']


@pytest.mark.asyncio
async def test_process_reports_http_and_malformed_responses(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    responses = [
        FetcherResponse(body='rate limited', status=429, headers={}),
        FetcherResponse(body={'unexpected': 'shape'}, status=200, headers={}),
    ]

    async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with caplog.at_level(logging.INFO, logger=arquivo.__name__):
        first = arquivo.SearchArquivo('example.com', 500)
        await first.process()
        second = arquivo.SearchArquivo('example.com', 500)
        await second.process()

    assert await first.get_hostnames() == set()
    assert await second.get_hostnames() == set()
    assert 'Arquivo.pt request failed with HTTP 429' in caplog.text
    assert 'Arquivo.pt returned malformed CDX data' in caplog.text
