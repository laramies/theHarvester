import asyncio
import json
import logging
from urllib.parse import parse_qs, urlsplit

import pytest
from aiohttp import web

from theHarvester.discovery import commoncrawl
from theHarvester.lib.core import FetcherResponse, ResponseStreamError


def install_fetcher(monkeypatch, fetch_all):
    """Serve catalog/count and bounded page requests from one protocol fixture."""

    async def fetch_text(url, **kwargs):
        assert kwargs['response_byte_limit'] == commoncrawl.SearchCommoncrawl.PAGE_RESPONSE_BYTES
        assert kwargs['request_timeout'] == 60
        payloads = await fetch_all([url], session=kwargs['session'])
        return FetcherResponse(body=payloads[0], status=200, headers={})

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_text', fetch_text)


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

        responses: list[object] = []
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

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    report = await search.process()

    assert report is None
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
        responses: list[object] = []
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

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('Example.COM.')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {'api.example.com', 'dev.example.com', 'example.com'}
    assert sum(current_endpoint in url for url in requested_urls) == 4
    assert sum(recent_endpoint in url for url in requested_urls) == 4
    assert all(old_endpoint not in url for url in requested_urls)


def test_unlimited_index_selection_has_no_local_history_window() -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        },
        {
            'id': 'CC-MAIN-2012',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2012-index',
            'to': '2012-12-31T00:00:00',
        },
    ]

    indexes = commoncrawl.SearchCommoncrawl._select_indexes(catalog, include_all=True)

    assert [index['id'] for index in indexes] == ['CC-MAIN-2026-30', 'CC-MAIN-2012']


@pytest.mark.asyncio
async def test_process_rejects_untrusted_catalog_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-HOSTILE',
            'cdx-api': 'https://internal.example/CC-MAIN-HOSTILE-index',
            'to': '2026-07-13T00:00:00',
        },
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        },
    ]
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        requested_urls.extend(urls)
        return ['{"pages": 0, "pageSize": 5, "blocks": 0}']

    install_fetcher(monkeypatch, fake_fetch_all)

    with caplog.at_level(logging.WARNING, logger=commoncrawl.__name__):
        await commoncrawl.SearchCommoncrawl('example.com').process()

    assert requested_urls
    assert all(url.startswith('https://index.commoncrawl.org/') for url in requested_urls)
    assert 'CC-MAIN-HOSTILE' in caplog.text


@pytest.mark.asyncio
async def test_process_requests_provider_pages_sequentially(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    page_batches: list[int] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 3, "pageSize": 5, "blocks": 3}']
        page_batches.append(len(urls))
        return [f'{{"url":"https://host-{parse_qs(urlsplit(url).query)["page"][0]}.example.com/"}}' for url in urls]

    install_fetcher(monkeypatch, fake_fetch_all)
    await commoncrawl.SearchCommoncrawl('example.com').process()

    assert page_batches == [1, 1, 1, 1, 1, 1]


@pytest.mark.asyncio
async def test_unlimited_process_exhausts_provider_reported_page_count(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    requested_pages: list[int] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 3, "pageSize": 5, "blocks": 3}']
        page = int(query['page'][0])
        requested_pages.append(page)
        return [f'{{"url":"https://host-{page}.example.com/"}}']

    install_fetcher(monkeypatch, fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com', limit=None)
    report = await search.process()

    assert requested_pages == [0, 1, 2, 0, 1, 2]
    assert await search.get_hostnames() == {'host-0.example.com', 'host-1.example.com', 'host-2.example.com'}
    assert report is None


@pytest.mark.asyncio
async def test_process_respects_the_result_limit_across_page_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    requested_pages: list[int] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 100, "pageSize": 5, "blocks": 500}']

        responses: list[object] = []
        for url in urls:
            page_query = parse_qs(urlsplit(url).query)
            page = int(page_query['page'][0])
            assert 'limit' not in page_query
            page_limit = 50
            requested_pages.append(page)
            responses.append('\n'.join(f'{{"url":"https://host-{page}-{result}.example.com/"}}' for result in range(page_limit)))
        return responses

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com', limit=51)
    report = await search.process()

    assert report is None
    assert requested_pages == [0, 1]
    assert len(await search.get_hostnames()) == 51


@pytest.mark.asyncio
async def test_process_counts_only_unique_in_scope_hosts_toward_the_result_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    requested_pages: list[int] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 6, "pageSize": 5, "blocks": 6}']

        responses: list[object] = []
        for url in urls:
            page = int(parse_qs(urlsplit(url).query)['page'][0])
            requested_pages.append(page)
            if page < 2:
                responses.append(
                    '{"url":"https://duplicate.example.com/one"}\n'
                    '{"url":"https://duplicate.example.com/two"}\n'
                    '{"url":"https://outside.example.net/"}'
                )
            elif page == 2:
                responses.append('{"url":"https://outside.example.net/"}')
            else:
                responses.append(f'{{"url":"https://host-{page}.example.com/"}}')
        return responses

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com', limit=3)
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {
        'duplicate.example.com',
        'host-3.example.com',
        'host-4.example.com',
    }
    assert requested_pages[:5] == [0, 1, 2, 3, 4]


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

        responses: list[object] = []
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

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    with caplog.at_level(logging.WARNING, logger=commoncrawl.__name__):
        report = await search.process()

    assert report is not None
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'
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

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    with caplog.at_level(logging.WARNING, logger=commoncrawl.__name__):
        report = await search.process()

    assert 'unexpected non-JSON response' in caplog.text
    assert report.status == 'failed'
    assert report.stop_reason == 'all-queries-failed'


@pytest.mark.asyncio
async def test_process_stops_a_query_after_three_entirely_unusable_pages(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    page_batches = 0

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        nonlocal page_batches
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 100, "pageSize": 5, "blocks": 500}']
        page_batches += 1
        return [''] * len(urls)

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    with caplog.at_level(logging.INFO, logger=commoncrawl.__name__):
        report = await search.process()

    assert page_batches == 6
    assert 'Common Crawl selected 1 index and 2 queries' in caplog.text
    assert 'example.com' not in caplog.text
    assert report.status == 'failed'
    assert report.stop_reason == 'all-queries-failed'


@pytest.mark.asyncio
async def test_process_retains_partial_results_at_the_runtime_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = [
        {
            'id': 'CC-MAIN-2026-30',
            'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
            'to': '2026-07-12T00:00:00',
        }
    ]
    count_requests = 0

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        nonlocal count_requests
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [catalog]
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            count_requests += 1
            if count_requests > 1:
                await asyncio.Event().wait()
            return ['{"pages": 1, "pageSize": 5, "blocks": 1}']
        return ['{"url":"https://api.example.com/"}']

    install_fetcher(monkeypatch, fake_fetch_all)
    monkeypatch.setattr(commoncrawl.SearchCommoncrawl, 'RUNTIME_SECONDS', 0.01)
    search = commoncrawl.SearchCommoncrawl('example.com')

    report = await asyncio.wait_for(search.process(), timeout=0.1)

    assert await search.get_hostnames() == {'api.example.com'}

    assert report.status == 'partial'
    assert report.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_process_reports_a_runtime_limit_before_collecting_results(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[object]:
        await asyncio.Event().wait()

    install_fetcher(monkeypatch, fake_fetch_all)
    monkeypatch.setattr(commoncrawl.SearchCommoncrawl, 'RUNTIME_SECONDS', 0.01)
    search = commoncrawl.SearchCommoncrawl('example.com')

    report = await asyncio.wait_for(search.process(), timeout=0.1)

    assert await search.get_hostnames() == set()
    assert report.status == 'failed'
    assert report.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_process_propagates_external_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    started = asyncio.Event()

    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[object]:
        started.set()
        await asyncio.Event().wait()

    install_fetcher(monkeypatch, fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com')
    task = asyncio.create_task(search.process())
    await started.wait()

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_process_keeps_later_valid_page_after_malformed_page(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
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
        query = parse_qs(urlsplit(urls[0]).query)
        if query.get('showNumPages') == ['true']:
            pages = 2 if query['url'] == ['*.example.com'] else 1
            return [f'{{"pages": {pages}, "pageSize": 5, "blocks": {pages}}}']
        if query['url'] == ['*.example.com']:
            return [
                'not-json' if parse_qs(urlsplit(url).query)['page'] == ['0'] else '{"url":"https://api.example.com/v1"}'
                for url in urls
            ]
        return ['<html><h1>504 Gateway Time-out</h1></html>']

    install_fetcher(monkeypatch, fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com')

    with caplog.at_level(logging.WARNING, logger=commoncrawl.__name__):
        report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert 'malformed JSON line' in caplog.text
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'


@pytest.mark.asyncio
async def test_process_isolates_malformed_urls_within_a_page(monkeypatch: pytest.MonkeyPatch) -> None:
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
        return [
            '{"url":"http://[bad"}\n{"url":123}\n{"url":"https://api.example.com/v1"}\n{"url":"https://mail.example.com/inbox"}'
        ]

    install_fetcher(monkeypatch, fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {'api.example.com', 'mail.example.com'}


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

    install_fetcher(monkeypatch, fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com')

    report = await search.process()

    assert report is not None
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'
    assert await search.get_hostnames() == {'api.example.com'}


pytestmark = pytest.mark.provider_contract('commoncrawl')


@pytest.mark.asyncio
@pytest.mark.parametrize(('limit', 'duplicate_count'), [(2, 2), (None, 50)])
async def test_complete_zipnum_page_is_not_truncated_before_hostname_dedup(monkeypatch, limit, duplicate_count):
    records = [{'url': 'https://a.example.test/path'}] * duplicate_count + [{'url': 'https://z.example.test/'}]

    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        query = parse_qs(urlsplit(urls[0]).query)
        if query['url'] == ['example.test/*']:
            return ['{"pages": 0}']
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 1, "pageSize": 5, "blocks": 1}']
        # CDX limit truncates captures within the ZipNum page; it does not resize that page.
        page = records[: int(query['limit'][0])] if 'limit' in query else records
        return ['\n'.join(json.dumps(row) for row in page)]

    install_fetcher(monkeypatch, fetch_all)
    source = commoncrawl.SearchCommoncrawl('example.test', limit=limit)
    report = await source.do_search(object())
    assert await source.get_hostnames() == {'a.example.test', 'z.example.test'}
    assert report is None


@pytest.mark.asyncio
@pytest.mark.parametrize('current_query', [False, True])
async def test_earlier_query_error_is_preserved_when_later_query_reaches_limit(monkeypatch, current_query):
    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        query = parse_qs(urlsplit(urls[0]).query)
        if not current_query and query['url'] == ['*.example.test']:
            return ['not-json']
        if query.get('showNumPages') == ['true']:
            return ['{"pages": 2}']
        if current_query and query['page'] == ['0']:
            return ['not-json']
        return ['{"url": "https://example.test/"}']

    install_fetcher(monkeypatch, fetch_all)
    source = commoncrawl.SearchCommoncrawl('example.test', limit=1)
    report = await source.do_search(object())
    assert await source.get_hostnames() == {'example.test'}
    assert report is not None
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'


@pytest.mark.asyncio
@pytest.mark.parametrize('prior_page', [False, True])
async def test_page_response_bound_stops_and_preserves_prior_hosts(monkeypatch, prior_page):
    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        return ['{"pages": 2}']

    calls = []

    async def fetch_text(url, **kwargs):
        assert kwargs['response_byte_limit'] == commoncrawl.SearchCommoncrawl.PAGE_RESPONSE_BYTES
        calls.append(url)
        if prior_page and len(calls) == 1:
            return FetcherResponse(body='{"url":"https://a.example.test/"}', status=200, headers={})
        raise ResponseStreamError('response-limit', status=200)

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_text', fetch_text)
    source = commoncrawl.SearchCommoncrawl('example.test', limit=None)
    report = await source.process()
    assert await source.get_hostnames() == ({'a.example.test'} if prior_page else set())
    assert report.status == ('partial' if prior_page else 'failed')
    assert report.stop_reason == 'response-limit'
    assert len(calls) == (2 if prior_page else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize('no_captures', [True, False])
async def test_page_http_404_distinguishes_no_captures_from_provider_failure(monkeypatch, no_captures):
    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        return ['{"pages": 1}']

    async def fetch_text(url, **kwargs):
        query = parse_qs(urlsplit(url).query)['url'][0]
        body = json.dumps({'error': f'No Captures found for: {query}'}) if no_captures else '<html>Not found</html>'
        return FetcherResponse(body=body, status=404, headers={})

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_text', fetch_text)
    source = commoncrawl.SearchCommoncrawl('example.test')
    report = await source.process()
    assert await source.get_hostnames() == set()
    if no_captures:
        assert report is None
    else:
        assert report.status == 'failed'
        assert report.stop_reason == 'all-queries-failed'


@pytest.mark.asyncio
@pytest.mark.parametrize('stop', ['complete', 'cancel', 'response-limit'])
async def test_page_conversation_preserves_cookies_and_closes_session(monkeypatch, unused_tcp_port, stop):
    cookies = []
    sessions = []
    original_fetch_text = commoncrawl.AsyncFetcher.fetch_text

    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        query = parse_qs(urlsplit(urls[0]).query)
        return ['{"pages": 2}'] if query['url'] == ['*.example.test'] else ['{"pages": 0}']

    async def fetch_text(url, **kwargs):
        sessions.append(kwargs['session'])
        if stop == 'cancel' and len(sessions) == 2:
            raise asyncio.CancelledError
        return await original_fetch_text(f'http://localhost:{unused_tcp_port}/page', **kwargs)

    async def page(request):
        cookies.append(request.cookies.get('page-session'))
        if len(cookies) > 1 and cookies[-1] != 'ready':
            return web.Response(status=403)
        host = f'page{len(cookies)}.example.test'
        body = json.dumps({'url': f'https://{host}/'})
        if stop == 'response-limit' and len(cookies) == 2:
            body += ' ' * 1000
        response = web.Response(text=body)
        response.set_cookie('page-session', 'ready')
        return response

    app = web.Application()
    app.router.add_get('/page', page)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.TCPSite(runner, '127.0.0.1', unused_tcp_port).start()
        monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fetch_all)
        monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_text', fetch_text)
        monkeypatch.setattr(commoncrawl.SearchCommoncrawl, 'PAGE_RESPONSE_BYTES', 100)
        source = commoncrawl.SearchCommoncrawl('example.test')
        if stop == 'cancel':
            with pytest.raises(asyncio.CancelledError):
                await source.process()
        else:
            report = await source.process()
            if stop == 'response-limit':
                assert report.status == 'partial'
                assert report.stop_reason == 'response-limit'
            else:
                assert report is None
        assert await source.get_hostnames() == (
            {'page1.example.test', 'page2.example.test'} if stop == 'complete' else {'page1.example.test'}
        )
        assert cookies == ([None] if stop == 'cancel' else [None, 'ready'])
        assert len(sessions) == 2
        assert sessions[0] is sessions[1]
        assert sessions[0].closed
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['http-503', 'transport-error'])
@pytest.mark.parametrize('failed_pages', [1, 3])
async def test_page_failures_preserve_later_coverage_until_consecutive_error_bound(monkeypatch, failure, failed_pages):
    requested_pages = []

    async def fetch_all(urls, **kwargs):
        if urls == ['https://index.commoncrawl.org/collinfo.json']:
            return [
                [
                    {
                        'id': 'CC-MAIN-2026-30',
                        'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-2026-30-index',
                        'to': '2026-07-12T00:00:00',
                    }
                ]
            ]
        query = parse_qs(urlsplit(urls[0]).query)
        return [json.dumps({'pages': failed_pages + 1 if query['url'] == ['*.example.test'] else 0})]

    async def fetch_text(url, **kwargs):
        page = int(parse_qs(urlsplit(url).query)['page'][0])
        requested_pages.append(page)
        if page < failed_pages:
            if failure == 'transport-error':
                raise ResponseStreamError('transport-error')
            return FetcherResponse(body='Unavailable', status=503, headers={})
        return FetcherResponse(body='{"url":"https://later.example.test/"}', status=200, headers={})

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_text', fetch_text)
    source = commoncrawl.SearchCommoncrawl('example.test')
    report = await source.process()
    assert requested_pages == ([0, 1] if failed_pages == 1 else [0, 1, 2])
    assert await source.get_hostnames() == ({'later.example.test'} if failed_pages == 1 else set())
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'
