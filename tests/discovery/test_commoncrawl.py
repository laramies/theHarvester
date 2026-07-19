import logging
from urllib.parse import parse_qs, urlsplit

import pytest

from theHarvester.discovery import commoncrawl


@pytest.mark.asyncio
async def test_process_exhausts_current_catalog_index_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]

    async def fake_fetch_all(urls: list[str], **kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            assert kwargs['json'] is True
            return [catalog]

        responses: list[str] = []
        for url in urls:
            query = parse_qs(urlsplit(url).query)
            if query.get('showNumPages') == ['true']:
                responses.append('{"pages": 2, "pageSize": 5, "blocks": 6}')
            elif query['url'] == ['*.example.com'] and query['page'] == ['0']:
                responses.append('{"url":"https://api.example.com/v1"}')
            elif query['url'] == ['*.example.com'] and query['page'] == ['1']:
                responses.append('{"url":"https://mail.example.com/inbox"}')
            elif query['url'] == ['example.com/*'] and query['page'] == ['0']:
                responses.append('{"url":"https://example.com/"}')
            else:
                responses.append('{"url":"https://www.example.com/about"}')
        return responses

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    await search.process()

    assert await search.get_hostnames() == {
        'api.example.com',
        'example.com',
        'mail.example.com',
        'www.example.com',
    }


@pytest.mark.asyncio
async def test_process_uses_unique_indexes_from_latest_catalog_year_window_and_scopes_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_endpoint = 'https://index.commoncrawl.org/CC-MAIN-2026-30-index'
    recent_endpoint = 'https://index.commoncrawl.org/CC-MAIN-2025-35-index'
    old_endpoint = 'https://index.commoncrawl.org/CC-MAIN-2024-30-index'
    catalog = [
        {'id': 'CC-MAIN-2026-30', 'cdx-api': current_endpoint, 'to': '2026-07-12T00:00:00'},
        {'id': 'CC-MAIN-2025-35', 'cdx-api': recent_endpoint, 'to': '2025-08-28T00:00:00'},
        {'id': 'CC-MAIN-2026-30-copy', 'cdx-api': current_endpoint, 'to': '2026-07-12T00:00:00'},
        {'id': 'CC-MAIN-2024-30', 'cdx-api': old_endpoint, 'to': '2024-07-22T00:00:00'},
    ]
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]

        requested_urls.extend(urls)
        responses: list[str] = []
        for url in urls:
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            if query.get('showNumPages') == ['true']:
                responses.append('{"pages": 1, "pageSize": 5, "blocks": 1}')
            elif parsed.path.endswith('CC-MAIN-2026-30-index') and query['url'] == ['*.example.com']:
                responses.append('{"url":"https://API.Example.COM./v1"}')
            elif parsed.path.endswith('CC-MAIN-2026-30-index'):
                responses.append('{"url":"https://example.com/"}')
            elif query['url'] == ['*.example.com']:
                responses.append('{"url":"https://api.example.com/duplicate"}\n{"url":"https://dev.example.com/"}')
            else:
                responses.append('{"url":"https://example.com.attacker.net/"}\n{"url":"https://notexample.com/"}')
        return responses

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('Example.COM.')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'dev.example.com', 'example.com'}
    assert sum(current_endpoint in url for url in requested_urls) == 4
    assert sum(recent_endpoint in url for url in requested_urls) == 4
    assert all(old_endpoint not in url for url in requested_urls)


@pytest.mark.asyncio
@pytest.mark.parametrize('broken_payload', ['not-json', ''])
async def test_process_reports_failed_or_malformed_index_without_discarding_other_results(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, broken_payload: str
) -> None:
    broken_endpoint = 'https://index.commoncrawl.org/CC-MAIN-2026-30-index'
    good_endpoint = 'https://index.commoncrawl.org/CC-MAIN-2026-26-index'
    catalog = [
        {'id': 'CC-MAIN-BROKEN', 'cdx-api': 'https://index.commoncrawl.org/broken-index'},
        {'id': 'CC-MAIN-2026-30', 'cdx-api': broken_endpoint, 'to': '2026-07-12T00:00:00'},
        {'id': 'CC-MAIN-2026-26', 'cdx-api': good_endpoint, 'to': '2026-06-18T00:00:00'},
    ]

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]

        responses: list[str] = []
        for url in urls:
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            if query.get('showNumPages') == ['true']:
                responses.append('{"pages": 1, "pageSize": 5, "blocks": 1}')
            elif parsed.path.endswith('CC-MAIN-2026-30-index'):
                responses.append(broken_payload)
            else:
                responses.append('{"url":"https://survivor.example.com/"}')
        return responses

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    with caplog.at_level(logging.WARNING, logger=commoncrawl.__name__):
        await search.process()

    assert await search.get_hostnames() == {'survivor.example.com'}
    assert 'CC-MAIN-BROKEN' in caplog.text
    assert 'CC-MAIN-2026-30' in caplog.text


@pytest.mark.asyncio
async def test_process_reports_non_json_upstream_response(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        if 'showNumPages=true' in urls[0]:
            return ['{"pages": 1, "pageSize": 5, "blocks": 1}']
        return ['<html><h1>504 Gateway Time-out</h1></html>']

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with (
        caplog.at_level(logging.WARNING, logger=commoncrawl.__name__),
        pytest.raises(RuntimeError, match='all Common Crawl queries failed'),
    ):
        await commoncrawl.SearchCommoncrawl('example.com').process()

    assert 'unexpected non-JSON response' in caplog.text


@pytest.mark.asyncio
async def test_process_keeps_results_when_another_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 1, "pageSize": 5, "blocks": 1}']
        if query['url'] == ['*.example.com']:
            return ['{"url":"https://api.example.com/v1"}']
        return ['<html><h1>504 Gateway Time-out</h1></html>']

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
