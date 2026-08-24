import asyncio
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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
    requested_limits: list[int] = []

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
            page_limit = int(page_query['limit'][0])
            requested_limits.append(page_limit)
            responses.append('\n'.join(f'{{"url":"https://host-{page}-{result}.example.com/"}}' for result in range(page_limit)))
        return responses

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = commoncrawl.SearchCommoncrawl('example.com', limit=51)
    report = await search.process()

    assert report is None
    assert requested_limits == [50, 1]
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)

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

    monkeypatch.setattr(commoncrawl.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = commoncrawl.SearchCommoncrawl('example.com')

    report = await search.process()

    assert report is not None
    assert report.status == 'partial'
    assert report.stop_reason == 'query-errors'
    assert await search.get_hostnames() == {'api.example.com'}


pytestmark = pytest.mark.provider_contract('commoncrawl')
