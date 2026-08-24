import json
import socket

import pytest

from theHarvester.discovery import windvane
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
async def test_authenticated_results_are_normalized_and_scoped(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: 'test-key')
    responses = {
        ('ListSubDomain', 1): {
            'code': 0,
            'data': {
                'list': [
                    {'domain': 'API.Example.TEST.'},
                    {'domain': 'www.notexample.test'},
                ]
            },
        },
        ('ListSubDomain', 2): {'code': 0, 'data': {'list': []}},
        ('ListDNS', 1): {
            'code': 0,
            'data': {
                'list': [
                    {'domain': 'Mail.Example.TEST.', 'answer': '203.0.113.10', 'answer_type': 'A'},
                    {'domain': 'api.notexample.test', 'answer': '198.51.100.1', 'answer_type': 'A'},
                ]
            },
        },
        ('ListDNS', 2): {'code': 0, 'data': {'list': []}},
        ('ListEmail', 1): {
            'code': 0,
            'data': {
                'list': [
                    {'email': 'Admin@Example.TEST'},
                    {'email': 'attacker@notexample.test'},
                ]
            },
        },
    }

    async def fake_post_fetch(url, headers=None, data=None, proxy=False):
        endpoint = url.rsplit('/', 1)[-1]
        page = json.loads(data)['page_request']['page']
        assert headers['X-Api-Key'] == 'test-key'
        return json.dumps(responses[(endpoint, page)])

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = windvane.SearchWindvane('example.test')
    await search.process()

    assert await search.get_hostnames() == {'api.example.test', 'mail.example.test'}
    assert await search.get_ips() == {'203.0.113.10'}
    assert await search.get_emails() == {'admin@example.test'}


@pytest.mark.asyncio
async def test_keyless_provider_failure_does_not_guess_dns_names(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: None)
    requests = 0

    async def fake_post_fetch(*_args, **_kwargs):
        nonlocal requests
        requests += 1
        return '{"code":1}'

    def unexpected_gethostbyname(_hostname: str) -> str:
        raise AssertionError('Windvane must not guess common DNS names')

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(socket, 'gethostbyname', unexpected_gethostbyname)

    search = windvane.SearchWindvane('example.test')
    await search.process()

    assert requests == 1
    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_authenticated_unlimited_search_follows_all_endpoint_pagination(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: 'test-key')
    requests: list[tuple[str, int, int]] = []

    async def fake_post_fetch(url, headers=None, data=None, proxy=False):
        endpoint = url.rsplit('/', 1)[-1]
        page_request = json.loads(data)['page_request']
        page = page_request['page']
        requests.append((endpoint, page, page_request['count']))
        last_pages = {'ListSubDomain': 4, 'ListDNS': 3, 'ListEmail': 2}
        last_page = last_pages[endpoint]
        if page > last_page:
            return json.dumps({'code': 0, 'data': {'list': [], 'has_more': False}})
        if endpoint == 'ListSubDomain':
            item = {'domain': f'sub-{page}.example.test'}
        elif endpoint == 'ListDNS':
            item = {'domain': f'dns-{page}.example.test', 'answer': f'203.0.113.{page}', 'answer_type': 'A'}
        else:
            item = {'email': f'user-{page}@example.test'}
        return json.dumps({'code': 0, 'data': {'list': [item], 'has_more': page < last_page}})

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = windvane.SearchWindvane('example.test', None)

    assert await search.process() is None
    assert 'sub-4.example.test' in await search.get_hostnames()
    assert 'dns-3.example.test' in await search.get_hostnames()
    assert 'user-2@example.test' in await search.get_emails()
    assert requests == [
        ('ListSubDomain', 1, 30),
        ('ListSubDomain', 2, 30),
        ('ListSubDomain', 3, 30),
        ('ListSubDomain', 4, 30),
        ('ListDNS', 1, 30),
        ('ListDNS', 2, 30),
        ('ListDNS', 3, 30),
        ('ListEmail', 1, 50),
        ('ListEmail', 2, 50),
    ]


@pytest.mark.asyncio
async def test_keyless_unlimited_search_reports_repeated_page(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: None)

    async def fake_post_fetch(*_args, **_kwargs):
        return json.dumps(
            {
                'code': 0,
                'data': {'list': [{'domain': 'api.example.test'}], 'has_more': True},
            }
        )

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = windvane.SearchWindvane('example.test', None)

    assert await search.process() == SourceExecutionReport('partial', 'repeated-page')
    assert await search.get_hostnames() == {'api.example.test'}


@pytest.mark.asyncio
async def test_keyless_unlimited_search_reports_provider_bound(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: None)
    calls = 0

    async def fake_post_fetch(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return json.dumps(
                {
                    'code': 0,
                    'data': {'list': [{'domain': 'api.example.test'}], 'has_more': True},
                }
            )
        return json.dumps({'code': 1, 'message': 'Unauthenticated request limit reached'})

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = windvane.SearchWindvane('example.test', None)

    assert await search.process() == SourceExecutionReport('partial', 'provider-limit')
    assert await search.get_hostnames() == {'api.example.test'}


@pytest.mark.asyncio
async def test_finite_limit_stops_each_windvane_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: 'test-key')
    requests: list[tuple[str, int, int]] = []

    async def fake_post_fetch(url, headers=None, data=None, proxy=False):
        endpoint = url.rsplit('/', 1)[-1]
        page_request = json.loads(data)['page_request']
        requests.append((endpoint, page_request['page'], page_request['count']))
        return json.dumps({'code': 0, 'data': {'list': [{}], 'has_more': True}})

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = windvane.SearchWindvane('example.test', 1)

    assert await search.process() == SourceExecutionReport('completed', 'result-limit')
    assert requests == [('ListSubDomain', 1, 1), ('ListDNS', 1, 1), ('ListEmail', 1, 1)]


pytestmark = pytest.mark.provider_contract('windvane')
