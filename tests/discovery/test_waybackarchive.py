import asyncio
import logging
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import waybackarchive


@pytest.mark.asyncio
async def test_process_collects_more_than_one_cdx_page(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = '\n'.join(f'https://host-{index}.example.com/path' for index in range(100))
    second_page = '\n'.join(f'https://host-{index}.example.com/path' for index in range(100, 125))
    resume_key = 'com%2Cexample%29%2F+20260101000000%21'
    requests: list[dict[str, list[str]]] = []
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        requested_urls.extend(urls)
        query = parse_qs(urlparse(urls[0]).query)
        requests.append(query)
        if query['url'] == ['*.example.com']:
            return [f'{first_page}\n\n{resume_key}'] if 'resumeKey' not in query else [second_page]
        return ['']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('example.com')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {f'host-{index}.example.com' for index in range(125)}
    assert [query.get('resumeKey') for query in requests if query['url'] == ['*.example.com']] == [
        None,
        ['com,example)/ 20260101000000!'],
    ]
    assert f'resumeKey={resume_key}' in requested_urls[1]
    assert all(query['showResumeKey'] == ['true'] for query in requests)


@pytest.mark.asyncio
async def test_process_stops_when_a_resume_key_repeats(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        query = parse_qs(urlparse(urls[0]).query)
        requests.append(query)
        if query['url'] == ['*.example.com']:
            return ['https://api.example.com/path\n\nrepeated-key']
        return ['']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('example.com')
    report = await search.process()

    assert report is None
    wildcard_requests = [query for query in requests if query['url'] == ['*.example.com']]
    assert len(wildcard_requests) == 2
    assert await search.get_hostnames() == {'api.example.com'}


@pytest.mark.asyncio
async def test_process_normalizes_and_scope_checks_each_page(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '\n'.join(
        (
            'HTTPS://API.Example.COM:8443/path',
            'https://example.com/root',
            'https://notexample.com/path',
            'https://example.com.attacker.net/path',
            'https://bad host.example.com/path',
            'malformed row',
        )
    )

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        query = parse_qs(urlparse(urls[0]).query)
        return [payload] if query['url'] == ['*.example.com'] else ['']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('example.com')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {'api.example.com', 'example.com'}


@pytest.mark.asyncio
async def test_process_normalizes_the_requested_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        query = parse_qs(urlparse(urls[0]).query)
        requests.append(query)
        return ['https://api.example.com/path'] if query['url'] == ['*.example.com'] else ['']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('Example.COM.')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == {'api.example.com'}
    assert requests[0]['url'] == ['*.example.com']


@pytest.mark.asyncio
async def test_process_keeps_partial_results_when_a_later_page_times_out(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        query = parse_qs(urlparse(urls[0]).query)
        if query['url'] == ['*.example.com']:
            if 'resumeKey' in query:
                raise TimeoutError
            return ['https://api.example.com/path\n\nnext-page']
        return ['https://example.com/path']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('example.com')
    with caplog.at_level(logging.INFO, logger=waybackarchive.__name__):
        report = await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'example.com'}
    assert 'Wayback Archive API error for pattern *.example.com' in caplog.text
    assert report.status == 'failed'
    assert report.stop_reason == 'request-error'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('payload', 'expected_log', 'expected_status', 'expected_stop_reason'),
    [
        ('', 'returned no page data', None, None),
        ('<html>provider error</html>', 'returned invalid page data', 'failed', 'invalid-response'),
        ({'unexpected': 'shape'}, 'returned invalid page data', 'failed', 'invalid-response'),
    ],
)
async def test_process_ignores_empty_html_and_non_text_responses(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    payload: object,
    expected_log: str,
    expected_status: str | None,
    expected_stop_reason: str | None,
) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        return [payload]

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = waybackarchive.SearchWaybackarchive('example.com')
    with caplog.at_level(logging.INFO, logger=waybackarchive.__name__):
        report = await search.process()

    assert await search.get_hostnames() == set()
    assert expected_log in caplog.text
    if expected_status is None:
        assert report is None
    else:
        assert report is not None
        assert report.status == expected_status
        assert report.stop_reason == expected_stop_reason


@pytest.mark.asyncio
async def test_process_continues_until_provider_exhaustion_without_a_page_bound(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    wildcard_requests = 0

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        nonlocal wildcard_requests
        query = parse_qs(urlparse(urls[0]).query)
        if query['url'] == ['*.example.com'] and wildcard_requests < 3:
            wildcard_requests += 1
            return [f'https://host-{wildcard_requests}.example.com/path\n\npage-{wildcard_requests}']
        return ['']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = waybackarchive.SearchWaybackarchive('example.com')
    with caplog.at_level(logging.INFO, logger=waybackarchive.__name__):
        report = await search.process()

    assert wildcard_requests == 3
    assert await search.get_hostnames() == {
        'host-1.example.com',
        'host-2.example.com',
        'host-3.example.com',
    }
    assert 'Wayback Archive page limit reached' not in caplog.text
    assert report is None


@pytest.mark.asyncio
async def test_process_retains_partial_results_at_the_runtime_limit(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    requests = 0

    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[str]:
        nonlocal requests
        requests += 1
        if requests == 1:
            return ['https://api.example.com/path\n\nnext-page']
        await asyncio.Event().wait()
        raise AssertionError('unreachable')

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(waybackarchive.SearchWaybackarchive, 'RUNTIME_SECONDS', 0.01)
    search = waybackarchive.SearchWaybackarchive('example.com')

    with caplog.at_level(logging.INFO, logger=waybackarchive.__name__):
        report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'partial'
    assert report.stop_reason == 'runtime-limit'
    assert 'Wayback Archive page 1: hosts=1' in caplog.text
    assert 'example.com' not in caplog.text


@pytest.mark.asyncio
async def test_process_reports_a_runtime_limit_before_collecting_results(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[str]:
        await asyncio.Event().wait()

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(waybackarchive.SearchWaybackarchive, 'RUNTIME_SECONDS', 0.01)
    search = waybackarchive.SearchWaybackarchive('example.com')

    report = await asyncio.wait_for(search.process(), timeout=0.1)

    assert await search.get_hostnames() == set()
    assert report.status == 'failed'
    assert report.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_process_stops_at_the_requested_result_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        requested_urls.extend(urls)
        return ['https://one.example.com/path\nhttps://two.example.com/path\nhttps://three.example.com/path\n\nnext-page']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = waybackarchive.SearchWaybackarchive('example.com', limit=2)

    report = await search.process()

    assert await search.get_hostnames() == {'one.example.com', 'two.example.com'}
    assert report is not None
    assert report.status == 'completed'
    assert report.stop_reason == 'result-limit'
    assert len(requested_urls) == 1


@pytest.mark.asyncio
async def test_process_keeps_an_earlier_failure_when_a_later_pattern_reaches_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[str]:
        query = parse_qs(urlparse(urls[0]).query)
        if query['url'] == ['*.example.com']:
            return ['<html>provider error</html>']
        return ['https://example.com/path']

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = waybackarchive.SearchWaybackarchive('example.com', limit=1)

    report = await search.process()

    assert await search.get_hostnames() == {'example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


pytestmark = pytest.mark.provider_contract('waybackarchive')
