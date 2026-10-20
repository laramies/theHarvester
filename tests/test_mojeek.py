import asyncio
import contextlib
from typing import Any

import pytest
from aiohttp import web

from theHarvester.discovery import mojeek
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_runner import SourceRequest, run_source


@pytest.mark.asyncio
@pytest.mark.parametrize('snippet', ['No results found', 'CAPTCHA help', 'Access denied', 'Temporarily blocked'])
async def test_result_snippets_are_not_provider_status_messages(monkeypatch, snippet):
    install_session(monkeypatch)

    async def fetch(**kwargs):
        return FetcherResponse(
            body=f'<ul class="results-standard"><li><a href="https://docs.example.test">{snippet}</a></li></ul>',
            status=200,
            headers={},
        )

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    outcome = await run_source(SourceRequest('mojeek', 'example.test', 10, 0, False, True))
    assert outcome.execution.status == 'completed'
    assert outcome.execution.stop_reason is None
    assert [observation.value for observation in outcome.observations] == ['docs.example.test']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    [
        '<style>.results-standard {display: block}</style><h1>Speed limit reached</h1>',
        '<h1>Speed <b>limit</b>\n reached</h1>',
        '<ul class="results-standard"></ul><h1>Speed limit reached</h1>',
    ],
)
async def test_speed_limit_page_is_identified_from_visible_message(monkeypatch, body):
    install_session(monkeypatch)

    async def fetch(**kwargs):
        return FetcherResponse(body=body, status=200, headers={})

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    outcome = await run_source(SourceRequest('mojeek', 'example.test', 10, 0, False, True))
    assert outcome.execution.status == 'rate-limited'
    assert outcome.execution.stop_reason == 'speed-limit-reached'
    assert outcome.observations == ()


@pytest.mark.asyncio
async def test_empty_results_container_stops_without_requesting_another_page(monkeypatch):
    install_session(monkeypatch)
    calls = []

    async def fetch(**kwargs):
        calls.append(kwargs)
        return FetcherResponse(body='<ul class="results-standard"></ul>', status=200, headers={})

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    outcome = await run_source(SourceRequest('mojeek', 'example.test', 500, 0, False, True))
    assert outcome.execution.status == 'completed'
    assert outcome.execution.stop_reason == 'no-results'
    assert outcome.observations == ()
    assert len(calls) == 1


@pytest.fixture(autouse=True)
def skip_page_delays(monkeypatch):
    async def sleep(delay):
        pass

    monkeypatch.setattr(mojeek.asyncio, 'sleep', sleep)


@pytest.mark.asyncio
@pytest.mark.parametrize('keyed', [False, True])
@pytest.mark.parametrize('cancel', [False, True])
async def test_page_conversation_keeps_cookies_and_closes_session(monkeypatch, unused_tcp_port, keyed, cancel):
    cookies = []
    sessions = []
    original_fetch = mojeek.AsyncFetcher.fetch

    async def fetch(**kwargs):
        session = kwargs['session']
        sessions.append(session)
        if cancel and len(sessions) == 2:
            raise asyncio.CancelledError
        kwargs['url'] = f'http://localhost:{unused_tcp_port}/search'
        return await original_fetch(**kwargs)

    async def search(request):
        cookies.append(request.cookies.get('page-session'))
        if len(cookies) == 1:
            body = {'response': {'results': [{'url': 'https://docs.example.test'}]}}
            response = (
                web.json_response(body) if keyed else web.Response(text='<ul class="results-standard">docs.example.test</ul>')
            )
            response.set_cookie('page-session', 'ready')
            return response
        if cookies[-1] != 'ready':
            return web.Response(status=403)
        return web.json_response({'response': {'results': []}}) if keyed else web.Response(text='No results found')

    app = web.Application()
    app.router.add_get('/search', search)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.TCPSite(runner, '127.0.0.1', unused_tcp_port).start()
        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key' if keyed else ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
        source = mojeek.SearchMojeek('example.test', 500)
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await source.process()
        else:
            assert await source.process() is None
        assert await source.get_hostnames() == ['docs.example.test']
        assert cookies == ([None] if cancel else [None, 'ready'])
        assert len(sessions) == 2
        assert sessions[0] is sessions[1]
        assert sessions[0].closed
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_speed_limit_phrase_in_search_result_is_not_a_denial(monkeypatch):
    install_session(monkeypatch)

    async def fetch(**kwargs):
        return FetcherResponse(
            body='<ul class="results-standard"><li>docs.example.test Speed limit reached</li></ul>', status=200, headers={}
        )

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    source = mojeek.SearchMojeek('example.test', 10)
    assert await source.process() is None
    assert await source.get_hostnames() == ['docs.example.test']


@pytest.mark.asyncio
@pytest.mark.parametrize('keyed', [False, True])
@pytest.mark.parametrize('limit', [20, 500, None])
async def test_pages_wait_two_seconds_before_next_request(monkeypatch, keyed, limit):
    install_session(monkeypatch)
    elapsed = 0.0
    requested_at = []

    async def sleep(delay):
        nonlocal elapsed
        elapsed += delay

    def response():
        requested_at.append(elapsed)
        if len(requested_at) == 2 and elapsed < 2:
            body = {'response': {'status': 'ERROR: Speed Limit Reached'}} if keyed else '<h1>Speed limit reached</h1>'
        elif len(requested_at) > 2:
            body = {'response': {'results': []}} if keyed else '<html>No results found</html>'
        else:
            host = f'page{len(requested_at)}.example.test'
            body = (
                {'response': {'results': [{'url': f'https://{host}'}]}} if keyed else f'<ul class="results-standard">{host}</ul>'
            )
        return FetcherResponse(body=body, status=200, headers={})

    async def fetch(**kwargs):
        return response()

    async def fetch_all(urls, **kwargs):
        assert len(urls) == 1
        return [response()]

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key' if keyed else ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(mojeek.asyncio, 'sleep', sleep)
    search = mojeek.SearchMojeek('example.test', limit)
    report = await search.process()
    assert await search.get_hostnames() == ['page1.example.test', 'page2.example.test']
    assert report is None
    assert requested_at == ([0.0, 2.0] if limit == 20 else [0.0, 2.0, 4.0])


@pytest.mark.asyncio
@pytest.mark.parametrize('keyed', [False, True])
@pytest.mark.parametrize('prior_page', [False, True])
async def test_speed_limit_is_reported_and_prior_evidence_survives(monkeypatch, keyed, prior_page):
    install_session(monkeypatch)
    bodies = []
    if prior_page:
        bodies.append(
            {'response': {'results': [{'url': 'https://docs.example.test'}]}}
            if keyed
            else '<ul class="results-standard">docs.example.test</ul>'
        )
    bodies.append({'response': {'status': 'ERROR: Speed Limit Reached'}} if keyed else '<h1>Speed limit reached</h1>')
    calls = []

    async def fetch(**kwargs):
        calls.append(kwargs)
        return FetcherResponse(body=bodies.pop(0), status=200, headers={})

    async def fetch_all(urls, **kwargs):
        assert len(urls) == 1
        return [await fetch(**kwargs)]

    async def sleep(delay):
        pass

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key' if keyed else ''))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fetch)
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fetch_all)
    monkeypatch.setattr(mojeek.asyncio, 'sleep', sleep)
    outcome = await run_source(SourceRequest('mojeek', 'example.test', 500, 0, False, True))
    assert outcome.execution.status == ('partial' if prior_page else 'rate-limited')
    assert outcome.execution.stop_reason == 'speed-limit-reached'
    assert [observation.value for observation in outcome.observations] == (['docs.example.test'] if prior_page else [])
    assert len(calls) == (2 if prior_page else 1)


def install_session(monkeypatch: pytest.MonkeyPatch) -> tuple[object, list[object]]:
    """Patch AsyncFetcher.open_session to yield one sentinel session per process call."""
    session = object()
    proxies: list[object] = []

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any):
        proxies.append(kwargs.get('proxy'))
        yield session

    monkeypatch.setattr(mojeek.AsyncFetcher, 'open_session', fake_open_session)
    return session, proxies


class TestMojeekSearch:
    @pytest.mark.asyncio
    async def test_unlimited_keyless_stops_when_provider_repeats_a_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []
        responses = iter(
            [
                FetcherResponse(body='<ul class="results-standard">one.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='<ul class="results-standard">two.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='<ul class="results-standard">two.example.com</ul>', status=200, headers={}),
            ]
        )

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return next(responses)

        async def fake_sleep(_delay: float) -> None:
            return None

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=None)

        report = await search.process()

        assert report == mojeek.SourceExecutionReport('partial', 'repeated-page')
        assert [call['url'] for call in calls] == [
            'https://www.mojeek.com/search?q=example.com&s=0',
            'https://www.mojeek.com/search?q=example.com&s=10',
            'https://www.mojeek.com/search?q=example.com&s=20',
        ]
        assert await search.get_hostnames() == ['one.example.com', 'two.example.com']

    @pytest.mark.asyncio
    async def test_unlimited_keyed_api_stops_when_provider_exhausts_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requests: list[list[str]] = []
        responses = iter(
            [
                FetcherResponse(body={'response': {'results': [{'url': 'https://one.example.com'}]}}, status=200, headers={}),
                FetcherResponse(body={'response': {'results': [{'url': 'https://two.example.com'}]}}, status=200, headers={}),
                FetcherResponse(body={'response': {'results': []}}, status=200, headers={}),
            ]
        )

        async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
            requests.append(urls)
            return [next(responses)]

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = mojeek.SearchMojeek(word='example.com', limit=None)

        report = await search.process()

        assert report is None
        assert requests == [
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1'],
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11'],
            ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=21'],
        ]
        assert await search.get_hostnames() == ['one.example.com', 'two.example.com']

    @pytest.mark.asyncio
    async def test_unlimited_keyed_api_reports_repeated_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        page = FetcherResponse(
            body={'response': {'results': [{'url': 'https://one.example.com'}]}},
            status=200,
            headers={},
        )

        async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
            return [page]

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)

        report = await mojeek.SearchMojeek(word='example.com', limit=None).process()

        assert report == mojeek.SourceExecutionReport('partial', 'repeated-page')

    @pytest.mark.asyncio
    async def test_keyless_later_http_failure_is_partial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = iter(
            [
                FetcherResponse(body='<ul class="results-standard">one.example.com</ul>', status=200, headers={}),
                FetcherResponse(body='unavailable', status=503, headers={}),
            ]
        )

        async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
            return next(responses)

        async def fake_sleep(_delay: float) -> None:
            return None

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)

        report = await mojeek.SearchMojeek(word='example.com', limit=None).process()

        assert report == mojeek.SourceExecutionReport('partial', 'http-503')

    @pytest.mark.asyncio
    async def test_mojeek_cancellation_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def cancel(**_kwargs: Any) -> FetcherResponse:
            raise asyncio.CancelledError('operator-stop')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', cancel)

        with pytest.raises(asyncio.CancelledError, match='operator-stop'):
            await mojeek.SearchMojeek(word='example.com', limit=None).process()

    @pytest.mark.asyncio
    async def test_keyless_pages_are_sequential_and_stop_after_first_empty_page(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session, session_proxies = install_session(monkeypatch)
        calls: list[dict[str, Any]] = []
        delays: list[float] = []
        responses = iter(
            [
                FetcherResponse(
                    body='<ul class="results-standard"><li>docs.example.com admin@example.com</li></ul>',
                    status=200,
                    headers={},
                ),
                FetcherResponse(body='<html>No results found</html>', status=200, headers={}),
                FetcherResponse(body='<html>must-not-run.example.com</html>', status=200, headers={}),
            ]
        )

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return next(responses)

        async def fake_sleep(delay: float) -> None:
            delays.append(delay)

        async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
            raise AssertionError('keyless Mojeek pages must be requested sequentially')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', reject_fetch_all)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=30)

        report = await search.process(proxy=True)

        assert session_proxies == [True]
        assert [call['url'] for call in calls] == [
            'https://www.mojeek.com/search?q=example.com&s=0',
            'https://www.mojeek.com/search?q=example.com&s=10',
        ]
        assert all(call['session'] is session for call in calls)
        assert all(call['include_metadata'] is True for call in calls)
        assert all(call['headers'] == {'User-Agent': 'UA'} for call in calls)
        assert all(call['follow_redirects'] is False for call in calls)
        assert delays == [2.0]
        assert await search.get_hostnames() == ['docs.example.com', 'example.com']
        assert await search.get_emails() == {'admin@example.com'}
        assert report is None

    @pytest.mark.parametrize(
        ('http_status', 'execution_status', 'stop_reason'),
        [(403, 'failed', 'access-denied'), (429, 'rate-limited', 'http-429')],
    )
    @pytest.mark.asyncio
    async def test_keyless_http_denial_is_attributed_before_pagination(
        self,
        monkeypatch: pytest.MonkeyPatch,
        http_status: int,
        execution_status: str,
        stop_reason: str,
    ) -> None:
        calls: list[dict[str, Any]] = []
        delays: list[float] = []

        async def fake_fetch(**kwargs: Any) -> FetcherResponse:
            calls.append(kwargs)
            return FetcherResponse(body='<html>Access denied</html>', status=http_status, headers={})

        async def fake_sleep(delay: float) -> None:
            delays.append(delay)

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        monkeypatch.setattr(mojeek.asyncio, 'sleep', fake_sleep)
        search = mojeek.SearchMojeek(word='example.com', limit=30)

        report = await search.process()

        assert len(calls) == 1
        assert calls[0]['follow_redirects'] is False
        assert delays == []
        assert report.status == execution_status
        assert report.stop_reason == stop_reason
        assert await search.get_hostnames() == []

    @pytest.mark.parametrize(
        ('body', 'execution_status', 'stop_reason'),
        [
            ('<html>Maintenance</html>', 'failed', 'invalid-response'),
            ('<html>Access denied</html>', 'failed', 'access-denied'),
            ('<html>Please complete the CAPTCHA</html>', 'failed', 'security-verification'),
        ],
    )
    @pytest.mark.asyncio
    async def test_keyless_200_error_pages_are_not_completed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        body: str,
        execution_status: str,
        stop_reason: str,
    ) -> None:
        async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
            return FetcherResponse(body=body, status=200, headers={})

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: ''))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', fake_fetch)
        search = mojeek.SearchMojeek(word='example.com', limit=10)

        report = await search.process()

        assert report.status == execution_status
        assert report.stop_reason == stop_reason
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_failed_keyed_api_does_not_fall_back_to_scraping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        session, session_proxies = install_session(monkeypatch)
        calls: list[dict[str, Any]] = []

        async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
            calls.append({'urls': urls, **kwargs})
            return [FetcherResponse(body={'status': 'Access denied'}, status=403, headers={})]

        async def reject_scrape(**_kwargs: Any) -> FetcherResponse:
            raise AssertionError('failed keyed API calls must not fall back to scraping')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', reject_scrape)
        search = mojeek.SearchMojeek(word='example.com', limit=10)

        report = await search.process(proxy=True)

        assert session_proxies == [True]
        assert len(calls) == 1
        assert calls[0]['session'] is session
        assert calls[0]['include_metadata'] is True
        assert report.status == 'failed'
        assert report.stop_reason == 'access-denied'
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_keyed_api_success_parses_results_without_scraping(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session, _session_proxies = install_session(monkeypatch)
        requests: list[dict[str, Any]] = []
        responses = iter(
            [
                FetcherResponse(
                    status=200,
                    headers={},
                    body={
                        'response': {
                            'results': [
                                {
                                    'url': 'https:\\/\\/Blog.Example.COM.\\/contact',
                                    'title': 'Contact Admin@Example.COM.',
                                    'desc': 'API docs at api.example.com; ignore outsider@example.net',
                                }
                            ]
                        }
                    },
                ),
                FetcherResponse(body={'response': {'results': []}}, status=200, headers={}),
            ]
        )

        async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
            requests.append({'urls': urls, **kwargs})
            return [next(responses)]

        async def reject_scrape(**_kwargs: Any) -> FetcherResponse:
            raise AssertionError('successful keyed API calls must not scrape')

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch', reject_scrape)

        search = mojeek.SearchMojeek(word='example.com', limit=20)
        report = await search.process(proxy=True)

        assert requests == [
            {
                'urls': ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1'],
                'session': session,
                'headers': {'User-Agent': 'UA'},
                'json': True,
                'include_metadata': True,
            },
            {
                'urls': ['https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11'],
                'session': session,
                'headers': {'User-Agent': 'UA'},
                'json': True,
                'include_metadata': True,
            },
        ]
        assert await search.get_emails() == {'admin@example.com'}
        assert set(await search.get_hostnames()) - {'example.com'} == {
            'api.example.com',
            'blog.example.com',
        }
        assert report is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('limit', 'expected_offsets'),
        [
            (1, ['s=1']),
            (10, ['s=1']),
            (11, ['s=1', 's=11']),
            (25, ['s=1', 's=11', 's=21']),
        ],
    )
    async def test_keyed_api_enumerates_every_page_covering_the_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
        limit: int,
        expected_offsets: list[str],
    ) -> None:
        requested_urls: list[str] = []

        async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
            requested_urls.extend(urls)
            offset = urls[0].rsplit('s=', 1)[1]
            return [
                FetcherResponse(
                    body={'response': {'results': [{'url': f'https://page-{offset}.example.com'}]}},
                    status=200,
                    headers={},
                )
            ]

        monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: 'test-key'))
        monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)

        search = mojeek.SearchMojeek(word='example.com', limit=limit)
        await search.process()

        assert requested_urls == [
            f'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&{offset}' for offset in expected_offsets
        ]


pytestmark = pytest.mark.provider_contract('mojeek')
