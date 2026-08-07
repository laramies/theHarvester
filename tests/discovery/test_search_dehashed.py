import logging

import pytest

from theHarvester.discovery import search_dehashed
from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.search_dehashed import SearchDehashed
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_before_network(monkeypatch, key) -> None:
    monkeypatch.setattr(search_dehashed.Core, 'dehashed_key', lambda: key)

    with pytest.raises(MissingKey):
        SearchDehashed('example.com')


@pytest.mark.asyncio
async def test_process_honors_limit_and_retains_only_normalized_evidence(monkeypatch) -> None:
    monkeypatch.setattr(search_dehashed.Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(search_dehashed.Core, 'get_user_agent', lambda: 'test-agent')
    payloads = []
    first_page = [
        {
            'email': ' User@Example.COM ',
            'ip_address': '192.0.2.1',
            'password': 'provider-secret-password',
            'hashed_password': 'provider-secret-hash',
        }
        for _ in range(100)
    ]
    second_page = [
        {'email': 'admin@example.com', 'ip_address': '2001:0db8::1', 'database_name': 'private-breach'} for _ in range(20)
    ]
    responses = iter(
        [
            FetcherResponse(body={'entries': first_page}, status=200, headers={}),
            FetcherResponse(body={'entries': second_page}, status=200, headers={}),
        ]
    )

    async def fake_post_fetch(url, **kwargs):
        payloads.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr(search_dehashed.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = SearchDehashed('example.com', limit=120)

    await search.process(proxy='http://proxy.example:8080')

    assert [request['json_body']['size'] for _, request in payloads] == [100, 20]
    assert all(request['proxy'] == 'http://proxy.example:8080' for _, request in payloads)
    assert all(request['include_metadata'] is True for _, request in payloads)
    assert await search.get_emails() == {'user@example.com', 'admin@example.com'}
    assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}
    assert 'provider-secret-password' not in repr(vars(search))
    assert 'provider-secret-hash' not in repr(vars(search))
    assert 'private-breach' not in repr(vars(search))


@pytest.mark.asyncio
async def test_non_json_response_body_is_not_logged(monkeypatch, caplog) -> None:
    async def fake_post_fetch(*args, **kwargs):
        return FetcherResponse(body='provider-secret-payload', status=200, headers={})

    monkeypatch.setattr(search_dehashed.Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(search_dehashed.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(search_dehashed.AsyncFetcher, 'post_fetch', fake_post_fetch)
    caplog.set_level(logging.INFO, logger=search_dehashed.__name__)
    search = SearchDehashed('example.com')

    await search.do_search()

    assert 'provider-secret-payload' not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_log'),
    [
        (FetcherResponse(body='provider-secret-auth-detail', status=401, headers={}), 'HTTP 401'),
        (FetcherResponse(body='provider-secret-auth-detail', status=403, headers={}), 'HTTP 403'),
        (FetcherResponse(body={'entries': []}, status=200, headers={}), None),
    ],
)
async def test_authorization_and_empty_responses_fail_closed_without_provider_detail(
    monkeypatch, caplog, response, expected_log
) -> None:
    monkeypatch.setattr(search_dehashed.Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(search_dehashed.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_post_fetch(*args, **kwargs):
        return response

    monkeypatch.setattr(search_dehashed.AsyncFetcher, 'post_fetch', fake_post_fetch)
    caplog.set_level(logging.INFO, logger=search_dehashed.__name__)
    search = SearchDehashed('example.com')

    await search.process()

    assert await search.get_emails() == set()
    assert await search.get_ips() == set()
    assert 'provider-secret-auth-detail' not in caplog.text
    if expected_log is not None:
        assert expected_log in caplog.text


@pytest.mark.asyncio
async def test_rate_limit_retries_once_and_preserves_earlier_page(monkeypatch, caplog) -> None:
    monkeypatch.setattr(search_dehashed.Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(search_dehashed.Core, 'get_user_agent', lambda: 'test-agent')
    responses = iter(
        [
            FetcherResponse(
                body={'entries': [{'email': 'first@example.com'} for _ in range(100)]},
                status=200,
                headers={},
            ),
            FetcherResponse(body='provider-secret-limit-detail', status=429, headers={'retry-after': '0'}),
            FetcherResponse(body={'entries': [{'email': 'second@example.com'}]}, status=200, headers={}),
        ]
    )
    payloads = []
    sleeps = []

    async def fake_post_fetch(url, **kwargs):
        payloads.append(kwargs['json_body'])
        return next(responses)

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(search_dehashed.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(search_dehashed.asyncio, 'sleep', fake_sleep)
    caplog.set_level(logging.INFO, logger=search_dehashed.__name__)
    search = SearchDehashed('example.com', limit=200)

    await search.process()

    assert [payload['page'] for payload in payloads] == [1, 2, 2]
    assert sleeps == [0.0]
    assert await search.get_emails() == {'first@example.com', 'second@example.com'}
    assert 'provider-secret-limit-detail' not in caplog.text
