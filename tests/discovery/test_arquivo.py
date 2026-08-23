import asyncio
import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import arquivo
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


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
async def test_process_paginates_to_the_operator_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []
    responses = ['{"url": "https://one.example.com"}\n{"url": "https://two.example.com"}', '{"url": "https://three.example.com"}']

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        return [FetcherResponse(body=responses.pop(0), status=200, headers={})]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(arquivo.SearchArquivo, 'PAGE_SIZE', 2)

    search = arquivo.SearchArquivo('example.com', 3)
    await search.process()

    queries = [parse_qs(urlparse(url).query) for url in requested_urls]
    assert [query['limit'] for query in queries] == [['2'], ['1']]
    assert 'offset' not in queries[0]
    assert queries[1]['offset'] == ['2']
    assert await search.get_hostnames() == {'one.example.com', 'two.example.com', 'three.example.com'}


@pytest.mark.asyncio
async def test_unlimited_request_pages_until_the_provider_is_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []
    responses = ['{"url": "https://one.example.com"}\n{"url": "https://two.example.com"}', '']

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        return [FetcherResponse(body=responses.pop(0), status=200, headers={})]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(arquivo.SearchArquivo, 'PAGE_SIZE', 2)

    report = await arquivo.SearchArquivo('example.com', None).process()

    queries = [parse_qs(urlparse(url).query) for url in requested_urls]
    assert [query['limit'] for query in queries] == [['2'], ['2']]
    assert queries[1]['offset'] == ['2']
    assert report is None


@pytest.mark.asyncio
async def test_unlimited_request_reports_repeated_page(monkeypatch: pytest.MonkeyPatch) -> None:
    body = '{"url": "https://one.example.com"}'

    async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=body, status=200, headers={})]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(arquivo.SearchArquivo, 'PAGE_SIZE', 1)

    assert await arquivo.SearchArquivo('example.com', None).process() == SourceExecutionReport('partial', 'repeated-page')


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
        first_report = await first.process()
        second = arquivo.SearchArquivo('example.com', 500)
        second_report = await second.process()

    assert first_report == SourceExecutionReport('failed', 'http-429')
    assert second_report == SourceExecutionReport('failed', 'invalid-response')
    assert await first.get_hostnames() == set()
    assert await second.get_hostnames() == set()
    assert 'Arquivo.pt request failed with HTTP 429' in caplog.text
    assert 'Arquivo.pt returned malformed CDX data' in caplog.text


@pytest.mark.asyncio
async def test_later_arquivo_failure_preserves_partial_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(body='{"url": "https://one.example.com"}', status=200, headers={}),
        FetcherResponse(body='unavailable', status=503, headers={}),
    ]

    async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        return [responses.pop(0)]

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(arquivo.SearchArquivo, 'PAGE_SIZE', 1)
    search = arquivo.SearchArquivo('example.com', None)

    assert await search.process() == SourceExecutionReport('partial', 'http-503')
    assert await search.get_hostnames() == {'one.example.com'}


@pytest.mark.asyncio
async def test_arquivo_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancel(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(arquivo.AsyncFetcher, 'fetch_all', cancel)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await arquivo.SearchArquivo('example.com', None).process()


pytestmark = pytest.mark.provider_contract('arquivo')
