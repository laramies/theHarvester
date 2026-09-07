import asyncio
import ssl

import pytest
from aiohttp import ClientError, ClientSession, web

from theHarvester.discovery import bravesearch, censysearch, githubcode, hudsonrocksearch, leakix, search_dehashed
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.lib.source_runner import SOURCE_FACTORIES, SourceRequest, run_source


@pytest.mark.asyncio
async def test_brave_pagination_preserves_provider_cookies(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    requests: list[tuple[str | None, str | None]] = []
    sessions: list[ClientSession] = []
    original_build_session = bravesearch.AsyncFetcher._build_session

    async def tracked_build_session(*args: object, **kwargs: object) -> ClientSession:
        session = await original_build_session(*args, **kwargs)  # type: ignore[arg-type]
        sessions.append(session)
        return session

    monkeypatch.setattr(bravesearch.AsyncFetcher, '_build_session', tracked_build_session)

    async def search(request: web.Request) -> web.Response:
        offset = request.query.get('offset')
        requests.append((offset, request.cookies.get('provider-session')))
        if offset == '0':
            response = web.json_response(
                {
                    'query': {'more_results_available': True},
                    'web': {
                        'results': [
                            {
                                'title': 'First',
                                'description': 'one.example.com',
                                'url': 'https://one.example.com',
                            }
                        ]
                    },
                }
            )
            response.set_cookie('provider-session', 'ready')
            return response
        if request.cookies.get('provider-session') != 'ready':
            return web.json_response({'error': 'missing provider session'}, status=403)
        return web.json_response(
            {
                'query': {'more_results_available': False},
                'web': {
                    'results': [
                        {
                            'title': 'Second',
                            'description': 'two.example.com',
                            'url': 'https://two.example.com',
                        }
                    ]
                },
            }
        )

    app = web.Application()
    app.router.add_get('/search', search)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', unused_tcp_port)
    await site.start()
    monkeypatch.setattr(bravesearch, 'get_delay', lambda: 0)

    try:
        source = bravesearch.SearchBrave(
            'example.com',
            limit=2,
            credential_adapter=InMemoryCredentialAdapter({'brave': {'key': 'test-token'}}),
        )
        source.server = f'http://localhost:{unused_tcp_port}/search'
        report = await source.process()
    finally:
        await runner.cleanup()

    assert requests == [('0', None), ('1', 'ready')]
    assert await source.get_hostnames() == ['one.example.com', 'two.example.com']
    assert report == SourceExecutionReport('completed', 'result-limit')
    assert len(sessions) == 1
    assert sessions[0].closed is True


@pytest.mark.asyncio
async def test_censys_pagination_preserves_provider_cookies(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    requests: list[tuple[str | None, str | None]] = []

    async def search(request: web.Request) -> web.Response:
        body = await request.json()
        page_token = body.get('page_token')
        requests.append((page_token, request.cookies.get('provider-session')))
        if page_token is None:
            response = web.json_response(
                {
                    'result': {
                        'hits': [{'certificate_v1': {'resource': {'names': ['one.example.com']}}}],
                        'next_page_token': 'page-two',
                    }
                }
            )
            response.set_cookie('provider-session', 'ready')
            return response
        if request.cookies.get('provider-session') != 'ready':
            return web.json_response({'error': 'missing provider session'}, status=403)
        return web.json_response(
            {
                'result': {
                    'hits': [{'certificate_v1': {'resource': {'names': ['two.example.com']}}}],
                    'next_page_token': '',
                }
            }
        )

    app = web.Application()
    app.router.add_post('/search', search)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', unused_tcp_port)
    await site.start()
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('platform-token', None))
    monkeypatch.setattr(censysearch.SearchCensys, 'SERVER', f'http://localhost:{unused_tcp_port}/search')

    try:
        source = censysearch.SearchCensys('example.com', limit=2)
        report = await source.process()
    finally:
        await runner.cleanup()

    assert requests == [(None, None), ('page-two', 'ready')]
    assert await source.get_hostnames() == {'one.example.com', 'two.example.com'}
    assert report is None


@pytest.mark.asyncio
async def test_github_code_pagination_preserves_provider_cookies(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    requests: list[tuple[str | None, str | None]] = []

    async def search(request: web.Request) -> web.Response:
        page = request.query.get('page')
        requests.append((page, request.cookies.get('provider-session')))
        if page == '1':
            response = web.json_response(
                {'items': [{'text_matches': [{'fragment': 'first@example.com'}]}]},
                headers={'Link': f'<http://localhost:{unused_tcp_port}/search/code?q=example.com&page=2>; rel="next"'},
            )
            response.set_cookie('provider-session', 'ready')
            return response
        if request.cookies.get('provider-session') != 'ready':
            return web.json_response({'error': 'missing provider session'}, status=403)
        return web.json_response({'items': [{'text_matches': [{'fragment': 'second@example.com'}]}]})

    app = web.Application()
    app.router.add_get('/search/code', search)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', unused_tcp_port)
    await site.start()
    monkeypatch.setattr(githubcode.Core, 'github_key', lambda: 'github-token')
    monkeypatch.setattr(githubcode, 'get_delay', lambda: 0)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(githubcode.asyncio, 'sleep', no_sleep)

    try:
        source = githubcode.SearchGithubCode('example.com', limit=2)
        source.base_url = f'http://localhost:{unused_tcp_port}/search/code?q=example.com'
        await source.process()
    finally:
        await runner.cleanup()

    assert requests == [('1', None), ('2', 'ready')]
    assert source.counter == 2
    assert await source.get_emails() == {'first@example.com', 'second@example.com'}


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['dehashed', 'leakix', 'hudsonrock'])
@pytest.mark.parametrize('later_failure', [False, True])
async def test_repaired_provider_conversation_preserves_cookies_and_evidence(
    monkeypatch, unused_tcp_port, provider, later_failure
) -> None:
    monkeypatch.setattr(Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'get_user_agent', lambda: 'test-agent')
    sessions = []
    original_build_session = AsyncFetcher._build_session

    async def tracked_build_session(*args, **kwargs):
        session = await original_build_session(*args, **kwargs)
        sessions.append(session)
        return session

    monkeypatch.setattr(AsyncFetcher, '_build_session', tracked_build_session)
    cookies = []
    pages = []

    async def search(request):
        cookie = request.cookies.get('provider-session')
        cookies.append(cookie)
        assert request.headers['User-Agent'] == 'test-agent'
        if provider == 'dehashed':
            assert request.headers['Dehashed-Api-Key'] == 'test-key'
            payload = await request.json()
            pages.append(payload['page'])
            assert payload == {
                'query': 'example.test',
                'page': payload['page'],
                'size': 100,
                'wildcard': False,
                'regex': False,
                'de_dupe': False,
            }
            if len(cookies) == 1:
                response = web.json_response({'entries': [{'email': 'first@example.test'}] * 100})
                response.set_cookie('provider-session', 'ready')
                return response
        elif provider == 'leakix':
            assert request.headers['api-key'] == 'test-key'
            assert request.headers['accept'] == 'application/json'
        if len(cookies) == (2 if provider == 'dehashed' else 1):
            response = web.json_response({}, status=429, headers={'retry-after': '0', 'x-limited-for': '0ms'})
            response.set_cookie('provider-session', 'ready')
            return response
        if cookie != 'ready':
            return web.json_response({}, status=403)
        if later_failure and (provider != 'hudsonrock' or 'search-by-email' in request.path):
            return web.json_response({}, status=503)
        body = {
            'dehashed': {'entries': [{'email': 'second@example.test'}]},
            'leakix': [{'subdomain': 'portal.example.test'}],
            'hudsonrock': (
                {'stealers': []}
                if 'search-by-email' in request.path
                else {'data': {'employees_urls': [{'url': 'https://portal.example.test'}], 'emails': ['analyst@example.test']}}
            ),
        }[provider]
        return web.json_response(body)

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', search)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', unused_tcp_port).start()
    base_url = f'http://localhost:{unused_tcp_port}'
    try:
        for _ in range(2):
            cookies.clear()
            pages.clear()
            if provider == 'dehashed':
                source = search_dehashed.SearchDehashed('example.test', limit=200)
                source.api = base_url
            elif provider == 'leakix':
                source = leakix.SearchLeakix('example.test')
                source.url = base_url
            else:
                source = hudsonrocksearch.SearchHudsonRock('analyst@example.test')
                source.base_url = base_url
                source.request_delay = 0
            monkeypatch.setitem(SOURCE_FACTORIES, provider, lambda _request: source)
            outcome = await run_source(SourceRequest(provider, source.word, 200, 0, False, True))
            expected_status = ('failed' if provider == 'leakix' else 'partial') if later_failure else 'completed'
            assert outcome.execution.status == expected_status
            assert outcome.execution.stop_reason == ('http-503' if later_failure else None)
            assert outcome.execution.result_count == (
                0 if later_failure and provider == 'leakix' else 2 if provider == 'dehashed' and not later_failure else 1
            )
            assert cookies == ([None, 'ready'] if provider == 'leakix' else [None, 'ready', 'ready'])
            if provider == 'dehashed':
                assert pages == [1, 2, 2]
                assert await source.get_emails() == (
                    {'first@example.test'} if later_failure else {'first@example.test', 'second@example.test'}
                )
            else:
                assert await source.get_hostnames() == (
                    set() if later_failure and provider == 'leakix' else {'portal.example.test'}
                )
            assert sessions[-1].closed
            assert sessions[-1].timeout.total == (720 if provider == 'dehashed' else 60)
        assert len(sessions) == 2
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['dehashed', 'leakix', 'hudsonrock'])
@pytest.mark.parametrize('stage', ['opening', 'request', 'closing'])
@pytest.mark.parametrize(
    'error_type', [OSError, ClientError, ResponseStreamError, ValueError, RuntimeError, asyncio.CancelledError]
)
async def test_repaired_provider_session_failure_and_cancellation(monkeypatch, provider, stage, error_type) -> None:
    monkeypatch.setattr(Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'leakix_key', lambda: 'test-key')
    source = {
        'dehashed': lambda: search_dehashed.SearchDehashed('example.test', limit=1),
        'leakix': lambda: leakix.SearchLeakix('example.test'),
        'hudsonrock': lambda: hudsonrocksearch.SearchHudsonRock('example.test'),
    }[provider]()
    source.max_retries = 1
    opened = []
    closed = []
    owner = asyncio.current_task()
    error = error_type('response-limit' if error_type is ResponseStreamError else 'test interruption')

    class Session:
        async def close(self):
            closed.append(True)
            if stage == 'closing':
                if error_type is asyncio.CancelledError:
                    owner.cancel()
                    await asyncio.sleep(0)
                    return
                raise error

    session = Session()

    async def build_session(headers, client_timeout, proxy_url, proxy_type, ssl_context, cookie_jar):
        opened.append((client_timeout, proxy_url, proxy_type, ssl_context, cookie_jar))
        if stage == 'opening':
            raise error
        return session

    def resolve_proxy(required):
        assert required is True
        return 'http://127.0.0.1:9', 'http'

    async def fetch(*_args, **kwargs):
        assert kwargs['session'] is session
        assert not kwargs.get('proxy')
        if stage == 'request':
            raise error
        response = FetcherResponse(
            {
                'dehashed': {'entries': [{'email': 'first@example.test'}]},
                'leakix': [{'subdomain': 'portal.example.test'}],
                'hudsonrock': {'data': {'employees_urls': [{'url': 'https://portal.example.test'}]}},
            }[provider],
            200,
            {},
        )
        return response if provider == 'dehashed' else [response]

    monkeypatch.setattr(AsyncFetcher, '_build_session', build_session)
    monkeypatch.setattr(AsyncFetcher, '_resolve_proxy', resolve_proxy)
    monkeypatch.setattr(AsyncFetcher, 'post_fetch', fetch)
    monkeypatch.setattr(AsyncFetcher, 'fetch_all', fetch)
    if error_type is asyncio.CancelledError or (stage != 'request' and error_type in (ValueError, RuntimeError)):
        with pytest.raises(error_type):
            await source.process(proxy=True)
    else:
        reason = 'response-limit' if error_type is ResponseStreamError else 'transport-error'
        assert await source.process(proxy=True) == SourceExecutionReport('failed', reason)
    assert len(opened) == 1
    timeout, proxy_url, proxy_type, ssl_context, cookie_jar = opened[0]
    assert (proxy_url, proxy_type) == ('http://127.0.0.1:9', 'http')
    assert timeout.total == (720 if provider == 'dehashed' else 60)
    assert ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert cookie_jar is None
    assert closed == ([] if stage == 'opening' else [True])
    evidence = await source.get_emails() if provider == 'dehashed' else await source.get_hostnames()
    assert bool(evidence) is (stage == 'closing')


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['dehashed', 'hudsonrock'])
async def test_provider_cancellation_checkpoints_earlier_evidence(monkeypatch, provider) -> None:
    monkeypatch.setattr(Core, 'dehashed_key', lambda: 'test-key')
    if provider == 'dehashed':
        source = search_dehashed.SearchDehashed('example.test', limit=200)
    else:
        source = hudsonrocksearch.SearchHudsonRock('analyst@example.test')
        source.request_delay = 0
    monkeypatch.setitem(SOURCE_FACTORIES, provider, lambda _request: source)
    sessions = []

    async def fetch(*_args, **kwargs):
        sessions.append(kwargs['session'])
        if len(sessions) == 2:
            raise asyncio.CancelledError
        response = FetcherResponse(
            {'entries': [{'email': 'first@example.test'}] * 100}
            if provider == 'dehashed'
            else {'data': {'emails': ['first@example.test']}},
            200,
            {},
        )
        return response if provider == 'dehashed' else [response]

    monkeypatch.setattr(AsyncFetcher, 'post_fetch', fetch)
    monkeypatch.setattr(AsyncFetcher, 'fetch_all', fetch)
    checkpoints = []
    with pytest.raises(asyncio.CancelledError):
        await run_source(SourceRequest(provider, source.word, 200, 0, False, True), commit_cancelled=checkpoints.append)

    assert len(sessions) == 2
    assert sessions[0] is sessions[1]
    assert sessions[0].closed
    assert len(checkpoints) == 1
    outcome = checkpoints[0]
    assert (outcome.execution.status, outcome.execution.stop_reason) == ('partial', 'cancelled')
    assert [(observation.kind, observation.value) for observation in outcome.observations] == [('email', 'first@example.test')]
