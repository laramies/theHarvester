import pytest
from aiohttp import web

from theHarvester.discovery import censysearch, githubcode


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
        await source.process()
    finally:
        await runner.cleanup()

    assert requests == [(None, None), ('page-two', 'ready')]
    assert await source.get_hostnames() == {'one.example.com', 'two.example.com'}
    assert source.execution_status == 'completed'


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
