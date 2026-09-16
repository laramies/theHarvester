import asyncio
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from theHarvester.discovery import jsmon
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse, ProxyUnavailableError, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.lib.source_runner import SourceRequest, run_source

pytestmark = pytest.mark.provider_contract('jsmon')


def page(values, number=1, pages=1):
    return FetcherResponse({'subdomains': values, 'page': number, 'total_pages': pages}, 200, {})


@pytest.fixture
def conversation(monkeypatch):
    state = {'calls': [], 'closed': False, 'responses': []}
    session = object()

    @asynccontextmanager
    async def open_session(**kwargs):
        state['options'] = kwargs
        try:
            yield session
        finally:
            state['closed'] = True

    async def fetch(**kwargs):
        assert kwargs['session'] is session
        assert kwargs['json'] and kwargs['include_metadata']
        assert kwargs['follow_redirects'] is False
        state['calls'].append(kwargs)
        response = state['responses'].pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(jsmon.Core, 'jsmon_key', lambda: 'test-key')
    monkeypatch.setattr(jsmon.AsyncFetcher, 'open_session', open_session)
    monkeypatch.setattr(jsmon.AsyncFetcher, 'fetch', fetch)
    return state


async def test_paginated_scoped_results(conversation):
    conversation['responses'] = [
        page(['API.Example.COM.', 'api.example.com', 'outside.test'], pages=2),
        page(['www.example.com'], number=2, pages=2),
    ]
    source = jsmon.SearchJsmon('example.com', None)
    assert await source.process(proxy=True) is None
    assert await source.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert [call['params'] for call in conversation['calls']] == [{'page': 1}, {'page': 2}]
    assert all(call['url'] == 'https://subdomains.jsmon.sh/api/domain/example.com' for call in conversation['calls'])
    assert conversation['options']['headers']['Api-Key'] == 'test-key'
    assert conversation['options']['proxy'] is True
    assert conversation['closed']


async def test_result_limit_stops_before_second_request(conversation):
    conversation['responses'] = [page(['one.example.com', 'two.example.com'], pages=2)]
    source = jsmon.SearchJsmon('example.com', 1)
    assert await source.process() == SourceExecutionReport('completed', 'result-limit')
    assert await source.get_hostnames() == {'one.example.com'}
    assert len(conversation['calls']) == 1


@pytest.mark.parametrize(('response', 'expected'), [
    (None, SourceExecutionReport('failed', 'transport-error')),
    (FetcherResponse({}, 401, {}), SourceExecutionReport('failed', 'access-denied')),
    (FetcherResponse({}, 403, {}), SourceExecutionReport('partial', 'quota-exhausted')),
    (FetcherResponse({}, 404, {}), None),
    (FetcherResponse({}, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
    (FetcherResponse({}, 500, {}), SourceExecutionReport('failed', 'http-500')),
    (FetcherResponse('not json', 200, {}), SourceExecutionReport('failed', 'invalid-response')),
    (page('not a list'), SourceExecutionReport('failed', 'invalid-response')),
    (page([], pages='2'), SourceExecutionReport('failed', 'invalid-response')),
    (page([], number=True), SourceExecutionReport('failed', 'invalid-response')),
    (page([], pages=2), SourceExecutionReport('failed', 'invalid-response')),
    (page([], pages=0), None),
    (page([]), None),
    (TimeoutError('private payload'), SourceExecutionReport('failed', 'transport-error')),
    (ProxyUnavailableError('private payload'), SourceExecutionReport('failed', 'proxy-unavailable')),
    (ResponseStreamError('response-limit'), SourceExecutionReport('partial', 'response-limit')),
])
async def test_terminal_responses(conversation, response, expected, caplog):
    conversation['responses'] = [response]
    assert await jsmon.SearchJsmon('example.com', None).process() == expected
    assert conversation['closed']
    assert len(conversation['calls']) == 1
    assert 'private payload' not in caplog.text


@pytest.mark.parametrize('second', [FetcherResponse({}, 429, {}), FetcherResponse({}, 404, {}), page([], pages=2)])
async def test_runner_retains_evidence_after_later_failure(conversation, second):
    conversation['responses'] = [page(['one.example.com'], pages=2), second]
    result = await run_source(SourceRequest('jsmon', 'example.com', None, 0, False, True))
    assert result.execution.status == 'partial'
    assert result.execution.result_count == 1
    assert conversation['closed']


async def test_malformed_entry_keeps_valid_evidence(conversation):
    conversation['responses'] = [page(['ok.example.com', None])]
    source = jsmon.SearchJsmon('example.com', None)
    assert await source.process() == SourceExecutionReport('failed', 'invalid-response')
    assert await source.get_hostnames() == {'ok.example.com'}


async def test_cancellation_closes_session(conversation):
    conversation['responses'] = [asyncio.CancelledError()]
    with pytest.raises(asyncio.CancelledError):
        await jsmon.SearchJsmon('example.com', None).process()
    assert conversation['closed']


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_key(monkeypatch, key):
    monkeypatch.setattr(jsmon.Core, 'jsmon_key', lambda: key)
    with pytest.raises(MissingKey):
        jsmon.SearchJsmon('example.com', None)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_invalid_limit(monkeypatch, limit):
    monkeypatch.setattr(jsmon.Core, 'jsmon_key', lambda: 'test-key')
    with pytest.raises(ValueError):
        jsmon.SearchJsmon('example.com', limit)


async def test_credentials_and_readiness_use_only_yaml(monkeypatch):
    from theHarvester.lib.api.runs import list_sources

    monkeypatch.setenv('JSMON_KEY', 'ignored-env-key')
    monkeypatch.setattr(jsmon.Core, '_read_config', lambda _: 'apikeys: {}')
    assert jsmon.Core.jsmon_key() is None
    catalog = await list_sources('test-key')
    assert next(source for source in catalog.sources if source.name == 'jsmon').ready is False
    monkeypatch.setattr(jsmon.Core, '_read_config', lambda _: 'apikeys: {jsmon: {key: yaml-key}}')
    assert jsmon.Core.jsmon_key() == 'yaml-key'
    catalog = await list_sources('test-key')
    source = next(source for source in catalog.sources if source.name == 'jsmon')
    assert source.ready is True
    assert 'env-key' not in catalog.model_dump_json()
    assert 'yaml-key' not in catalog.model_dump_json()


async def test_pages_share_cookies_and_session_closes(monkeypatch, unused_tcp_port):
    requests = []
    sessions = []
    original_build = jsmon.AsyncFetcher._build_session

    async def build(*args, **kwargs):
        session = await original_build(*args, **kwargs)
        sessions.append(session)
        return session

    async def handler(request):
        number = int(request.query['page'])
        requests.append(number)
        assert request.headers['Api-Key'] == 'test-key'
        if number == 2 and request.cookies.get('conversation') != 'ready':
            return web.Response(status=401)
        response = web.json_response({
            'subdomains': [f'page{number}.example.com'], 'page': number, 'total_pages': 2,
        })
        response.set_cookie('conversation', 'ready')
        return response

    monkeypatch.setattr(jsmon.Core, 'jsmon_key', lambda: 'test-key')
    monkeypatch.setattr(jsmon.AsyncFetcher, '_build_session', build)
    app = web.Application()
    app.router.add_get('/api/domain/example.com', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.TCPSite(runner, '127.0.0.1', unused_tcp_port).start()
        source = jsmon.SearchJsmon('example.com', None)
        source.server = f'http://localhost:{unused_tcp_port}/api/domain/'
        assert await source.process() is None
    finally:
        await runner.cleanup()
    assert requests == [1, 2]
    assert await source.get_hostnames() == {'page1.example.com', 'page2.example.com'}
    assert len(sessions) == 1 and sessions[0].closed
