import logging
from typing import Any

import pytest

from theHarvester.discovery import huntersearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize('key', [None, '  '])
def test_hunter_rejects_missing_or_blank_key(monkeypatch, key) -> None:
    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: key)

    with pytest.raises(MissingKey):
        huntersearch.SearchHunter('example.test', 10, 0)


@pytest.mark.parametrize('status', [401, 403, 429])
@pytest.mark.asyncio
async def test_hunter_http_failures_return_no_results(monkeypatch, caplog, status: int) -> None:
    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'error': 'provider detail'}, status=status, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = huntersearch.SearchHunter('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=huntersearch.__name__):
        await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert f'Hunter request failed with HTTP {status}' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.parametrize(
    ('response', 'message'),
    [
        ([], 'Hunter request failed without a response'),
        ([FetcherResponse(body='not json', status=200, headers={})], 'Hunter returned malformed data'),
        ([FetcherResponse(body={}, status=200, headers={})], 'Hunter returned malformed data'),
    ],
)
@pytest.mark.asyncio
async def test_hunter_empty_or_malformed_response_returns_no_results(monkeypatch, caplog, response, message) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any):
        return response

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = huntersearch.SearchHunter('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=huntersearch.__name__):
        await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert message in caplog.text


@pytest.mark.asyncio
async def test_paid_hunter_search_honors_limit_and_offset(monkeypatch) -> None:
    requests: list[tuple[str, bool]] = []
    responses = iter(
        [
            {'data': {'plan_name': 'Growth', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {'data': {'total': 175}},
            {
                'data': {
                    'emails': [
                        {'value': 'alice@example.test', 'sources': [{'domain': 'api.example.test'}]},
                    ]
                }
            },
            {
                'data': {
                    'emails': [
                        {'value': 'bob@example.test', 'sources': [{'domain': 'www.example.test'}]},
                    ]
                }
            },
        ]
    )

    async def fake_fetch_all(urls, *, proxy=False, **_kwargs):
        requests.append((urls[0], proxy))
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(huntersearch.asyncio, 'sleep', no_sleep)

    search = huntersearch.SearchHunter('example.test', 150, 25)
    await search.process(proxy=True)

    assert requests == [
        ('https://api.hunter.io/v2/account?api_key=test-key', True),
        ('https://api.hunter.io/v2/email-count?domain=example.test', True),
        (
            'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=100&offset=25',
            True,
        ),
        (
            'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=50&offset=125',
            True,
        ),
    ]
    assert await search.get_emails() == ['alice@example.test', 'bob@example.test']
    assert await search.get_hostnames() == ['api.example.test', 'www.example.test']


@pytest.mark.asyncio
async def test_free_hunter_search_honors_limit_and_offset(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {'data': {'plan_name': 'Free', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {'data': {'emails': []}},
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', 5, 3)
    await search.process()

    assert requests == [
        'https://api.hunter.io/v2/account?api_key=test-key',
        'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=5&offset=3',
    ]


@pytest.mark.asyncio
async def test_paid_hunter_search_stops_before_exceeding_quota(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {'data': {'plan_name': 'Growth', 'requests': {'searches': {'available': 1, 'used': 0}}}},
            {'data': {'total': 250}},
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', 250, 0)
    await search.process()

    assert requests == [
        'https://api.hunter.io/v2/account?api_key=test-key',
        'https://api.hunter.io/v2/email-count?domain=example.test',
    ]
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
