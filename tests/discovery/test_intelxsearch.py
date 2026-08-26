from argparse import Namespace
from contextlib import asynccontextmanager
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import intelxsearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.completed_result import CompletedResult, ResultObservation


class _Response:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    async def json(self) -> object:
        return self.payload


class _Session:
    def __init__(self, result: object, search_result: object | None = None) -> None:
        self.result = list(result) if isinstance(result, list) else result
        self.search_result = {'success': True, 'id': 'search-id'} if search_result is None else search_result
        self.search_request: dict[str, object] | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def post(self, *_args, **kwargs) -> _Response:
        self.search_request = kwargs.get('json')
        return _Response(self.search_result)

    def get(self, *_args, **_kwargs) -> _Response:
        return _Response(self.result.pop(0) if isinstance(self.result, list) else self.result)


@pytest.fixture(autouse=True)
def proxy_aware_session(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    session_options: list[dict[str, Any]] = []

    @asynccontextmanager
    async def open_session(**kwargs: Any):
        session_options.append(kwargs)
        async with intelxsearch.aiohttp.ClientSession() as session:
            yield session

    monkeypatch.setattr(intelxsearch.AsyncFetcher, 'open_session', open_session)
    return session_options


def test_blank_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: '  '))

    with pytest.raises(MissingKey):
        intelxsearch.SearchIntelx('example.com')


@pytest.mark.asyncio
async def test_process_exposes_flat_normalized_in_scope_results(
    monkeypatch: pytest.MonkeyPatch,
    proxy_aware_session: list[dict[str, Any]],
) -> None:
    result = {
        'status': 1,
        'selectors': [
            {'selectorvalue': 'ADMIN@Example.COM'},
            {'selectorvalue': 'bad local@example.com'},
            {'selectorvalue': '<>@example.com'},
            {'selectorvalue': 'outsider@notexample.com'},
            {'selectorvalue': 'not@an@email@example.com'},
            {'selectorvalue': 'https://portal.example.com/path'},
            {'selectorvalue': 'api.example.com.'},
            {'selectorvalue': 'foo.example.com.evil'},
            {'selectorvalue': 'https://foo.example.com.evil/path'},
            {'selectorvalue': 'ftp://api.example.com/archive'},
            {'selectorvalue': 'http://['},
            {'selectorvalue': None},
            None,
        ],
    }
    session = _Session(result)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: session)
    monkeypatch.setattr(intelxsearch.asyncio, 'sleep', no_sleep)

    search = intelxsearch.SearchIntelx('example.com')
    await search.process(proxy=True)

    assert await search.get_emails() == ['admin@example.com']
    assert await search.get_hostnames() == ['api.example.com', 'portal.example.com']
    assert await search.get_urls() == ['https://portal.example.com/path']
    assert len(proxy_aware_session) == 1
    assert proxy_aware_session[0]['proxy'] is True


@pytest.mark.asyncio
async def test_unlimited_process_collects_provider_pages_until_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        {'status': 0, 'selectors': [{'selectorvalue': 'one.example.com'}]},
        {'status': 1, 'selectors': [{'selectorvalue': 'two.example.com'}]},
    ]
    session = _Session(pages)

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: session)

    search = intelxsearch.SearchIntelx('example.com', limit=None)

    assert await search.process() is None
    assert await search.get_hostnames() == ['one.example.com', 'two.example.com']
    assert session.search_request['maxresults'] == intelxsearch.SearchIntelx.UNLIMITED_QUERY_RESULTS


@pytest.mark.asyncio
async def test_finite_process_stops_after_requested_selector_count(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        {'status': 0, 'selectors': [{'selectorvalue': 'one.example.com'}, {'selectorvalue': 'two.example.com'}]},
        {'status': 1, 'selectors': [{'selectorvalue': 'three.example.com'}]},
    ]
    session = _Session(pages)

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: session)

    search = intelxsearch.SearchIntelx('example.com', limit=2)

    assert await search.process() is None
    assert await search.get_hostnames() == ['one.example.com', 'two.example.com']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('search_result', 'result'),
    [
        ({'success': False, 'message': 'denied'}, {}),
        ({}, {}),
        ({'success': True, 'id': 'search-id'}, None),
        ({'success': True, 'id': 'search-id'}, {'selectors': 'invalid'}),
    ],
)
async def test_process_treats_denied_and_malformed_responses_as_empty(
    monkeypatch: pytest.MonkeyPatch,
    search_result: object,
    result: object,
) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: _Session(result, search_result))
    monkeypatch.setattr(intelxsearch.asyncio, 'sleep', no_sleep)

    search = intelxsearch.SearchIntelx('example.com')
    await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert await search.get_urls() == []


@pytest.mark.asyncio
async def test_orchestrator_stores_intelx_subdomains_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    completed_results: list[CompletedResult] = []

    class _ResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class _Intelx:
        def __init__(self, _domain: str, _limit: int | None) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return ['example.com', 'api.example.com']

        async def get_emails(self) -> list[str]:
            return []

        async def get_urls(self) -> list[str]:
            return []

    class _UnexpectedChecker:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError('DNS resolution requires the explicit --dns-resolve flag')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _ResultStore)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _UnexpectedChecker)
    monkeypatch.setattr(intelxsearch, 'SearchIntelx', _Intelx)

    results = await theharvester_main.start(
        Namespace(
            source='intelx',
            dns_brute=False,
            filename='',
            quiet=True,
            dns_lookup=False,
            dns_server=None,
            dns_resolve='',
            limit=500,
            shodan=False,
            start=0,
            domain='Example.COM',
            take_over=False,
            proxies=False,
        ),
        persist_completed_result=True,
    )

    assert results[-1] == ['api.example.com']
    assert completed_results[0].observations == (ResultObservation('intelx', 'hostname', 'api.example.com'),)


pytestmark = pytest.mark.provider_contract('intelx')
