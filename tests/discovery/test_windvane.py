import json
import socket

import pytest

from theHarvester.discovery import windvane


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
