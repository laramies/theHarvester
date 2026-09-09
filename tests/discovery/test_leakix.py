import logging
from unittest.mock import ANY, AsyncMock

import pytest

from theHarvester.discovery import leakix
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_before_network(monkeypatch, key) -> None:
    monkeypatch.setattr(leakix.Core, 'leakix_key', lambda: key)

    with pytest.raises(MissingKey):
        leakix.SearchLeakix('example.com')


@pytest.mark.asyncio
async def test_process_uses_documented_endpoint_and_normalizes_only_scoped_subdomains(monkeypatch) -> None:
    monkeypatch.setattr(leakix.Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(leakix.Core, 'get_user_agent', lambda: 'test-agent')
    requests = []

    async def fake_fetch_all(urls, **kwargs):
        requests.append((urls, kwargs))
        return [
            FetcherResponse(
                body=[
                    {'subdomain': 'API.Example.COM.'},
                    {'subdomain': 'www.example.com'},
                    {'subdomain': 'example.com.attacker.test'},
                    {'subdomain': 7},
                    {'hostname': 'undocumented.example.com'},
                ],
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(leakix.AsyncFetcher, 'fetch_all', fake_fetch_all)
    session = AsyncMock()
    build_session = AsyncMock(return_value=session)
    monkeypatch.setattr(leakix.AsyncFetcher, '_build_session', build_session)
    monkeypatch.setattr(leakix.AsyncFetcher, '_resolve_proxy', lambda proxy: ('http://proxy.example:8080', 'http'))
    search = leakix.SearchLeakix('example.com')

    await search.process(proxy=True)

    assert requests == [
        (
            ['https://leakix.net/api/subdomains/example.com'],
            {
                'session': session,
                'json': True,
                'include_metadata': True,
            },
        )
    ]
    build_session.assert_awaited_once_with(
        {'User-Agent': 'test-agent', 'accept': 'application/json', 'api-key': 'test-key'},
        ANY,
        'http://proxy.example:8080',
        'http',
        ANY,
        None,
    )
    assert build_session.call_args.args[1].total == 60
    session.close.assert_awaited_once()
    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert await search.get_emails() == set()


@pytest.mark.asyncio
async def test_rate_limit_waits_for_provider_delay_and_retries_once(monkeypatch, caplog) -> None:
    monkeypatch.setattr(leakix.Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(leakix.Core, 'get_user_agent', lambda: 'test-agent')
    responses = iter(
        [
            FetcherResponse(
                body='provider-secret-limit-detail',
                status=429,
                headers={'x-limited-for': '0ms'},
            ),
            FetcherResponse(body=[{'subdomain': 'api.example.com'}], status=200, headers={}),
        ]
    )
    calls = []
    sleeps = []

    async def fake_fetch_all(*args, **kwargs):
        calls.append((args, kwargs))
        return [next(responses)]

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(leakix.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(leakix.asyncio, 'sleep', fake_sleep)
    caplog.set_level(logging.INFO, logger=leakix.__name__)
    search = leakix.SearchLeakix('example.com')

    await search.process()

    assert len(calls) == 2
    assert sleeps == [0.0]
    assert await search.get_hostnames() == {'api.example.com'}
    assert 'provider-secret-limit-detail' not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_log'),
    [
        (FetcherResponse(body='provider-secret-auth-detail', status=401, headers={}), 'HTTP 401'),
        (FetcherResponse(body='provider-secret-auth-detail', status=403, headers={}), 'HTTP 403'),
        (FetcherResponse(body={'subdomain': 'api.example.com'}, status=200, headers={}), 'malformed'),
        (FetcherResponse(body=[], status=200, headers={}), None),
        (None, 'request failed'),
    ],
)
async def test_unusable_responses_fail_closed_without_logging_provider_detail(
    monkeypatch, caplog, response, expected_log
) -> None:
    monkeypatch.setattr(leakix.Core, 'leakix_key', lambda: 'test-key')
    monkeypatch.setattr(leakix.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return [response]

    monkeypatch.setattr(leakix.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=leakix.__name__)
    search = leakix.SearchLeakix('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert 'provider-secret-auth-detail' not in caplog.text
    if expected_log is not None:
        assert expected_log in caplog.text


pytestmark = pytest.mark.provider_contract('leakix')
