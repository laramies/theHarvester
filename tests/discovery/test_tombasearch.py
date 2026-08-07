import logging
from typing import Any

import pytest

from theHarvester.discovery import tombasearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


def tomba_page(first: int, count: int = 50) -> dict:
    return {
        'data': {
            'emails': [
                {
                    'email': f'user{index}@example.test',
                    'sources': [{'website_url': f'user{index}.example.test'}],
                }
                for index in range(first, first + count)
            ]
        }
    }


@pytest.mark.parametrize(
    'credentials',
    [
        (None, 'test-secret'),
        ('test-key', None),
        ('  ', 'test-secret'),
        ('test-key', '  '),
    ],
)
def test_tomba_rejects_missing_or_blank_credentials(monkeypatch, credentials) -> None:
    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: credentials)

    with pytest.raises(MissingKey):
        tombasearch.SearchTomba('example.test', 10, 0)


@pytest.mark.parametrize('status', [401, 403, 429])
@pytest.mark.asyncio
async def test_tomba_http_failures_return_no_results(monkeypatch, caplog, status: int) -> None:
    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'error': 'provider detail'}, status=status, headers={})]

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = tombasearch.SearchTomba('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=tombasearch.__name__):
        await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert f'Tomba request failed with HTTP {status}' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.parametrize(
    ('response', 'message'),
    [
        ([], 'Tomba request failed without a response'),
        ([FetcherResponse(body='not json', status=200, headers={})], 'Tomba returned malformed data'),
        ([FetcherResponse(body={}, status=200, headers={})], 'Tomba returned malformed data'),
    ],
)
@pytest.mark.asyncio
async def test_tomba_empty_or_malformed_response_returns_no_results(monkeypatch, caplog, response, message) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any):
        return response

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = tombasearch.SearchTomba('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=tombasearch.__name__):
        await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert message in caplog.text


@pytest.mark.asyncio
async def test_paid_tomba_search_uses_documented_pages_and_page_size(monkeypatch) -> None:
    requests: list[tuple[str, bool]] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Growth'},
                    'requests': {'domains': {'available': 10, 'used': 0}},
                }
            },
            {'data': {'total': 175}},
            tomba_page(0),
            tomba_page(50),
            tomba_page(100),
        ]
    )

    async def fake_fetch_all(urls, *, proxy=False, **_kwargs):
        requests.append((urls[0], proxy))
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(tombasearch.asyncio, 'sleep', no_sleep)

    search = tombasearch.SearchTomba('example.test', 120, 0)
    await search.process(proxy=True)

    assert requests == [
        ('https://api.tomba.io/v1/me', True),
        ('https://api.tomba.io/v1/email-count?domain=example.test', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=1', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=2', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=3', True),
    ]
    emails = await search.get_emails()
    hostnames = await search.get_hostnames()
    assert len(emails) == 120
    assert len(hostnames) == 120
    assert 'user119@example.test' in emails
    assert 'user119.example.test' in hostnames
    assert 'user120@example.test' not in emails
    assert 'user120.example.test' not in hostnames


@pytest.mark.asyncio
async def test_paid_tomba_search_honors_nonzero_start(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Growth'},
                    'requests': {'domains': {'available': 10, 'used': 0}},
                }
            },
            {'data': {'total': 200}},
            tomba_page(50),
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(tombasearch.asyncio, 'sleep', no_sleep)

    search = tombasearch.SearchTomba('example.test', 20, 60)
    await search.process()

    assert requests == [
        'https://api.tomba.io/v1/me',
        'https://api.tomba.io/v1/email-count?domain=example.test',
        'https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=2',
    ]
    emails = await search.get_emails()
    assert len(emails) == 20
    assert 'user60@example.test' in emails
    assert 'user79@example.test' in emails
    assert 'user59@example.test' not in emails
    assert 'user80@example.test' not in emails


@pytest.mark.asyncio
async def test_paid_tomba_search_preserves_first_page_after_rate_limit(monkeypatch, caplog) -> None:
    requests: list[str] = []
    responses = iter(
        [
            FetcherResponse(
                body={
                    'data': {
                        'pricing': {'name': 'Growth'},
                        'requests': {'domains': {'available': 10, 'used': 0}},
                    }
                },
                status=200,
                headers={},
            ),
            FetcherResponse(body={'data': {'total': 175}}, status=200, headers={}),
            FetcherResponse(body=tomba_page(0), status=200, headers={}),
            FetcherResponse(body={'error': 'provider detail'}, status=429, headers={}),
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [next(responses)]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(tombasearch.asyncio, 'sleep', no_sleep)
    search = tombasearch.SearchTomba('example.test', 120, 0)

    with caplog.at_level(logging.INFO, logger=tombasearch.__name__):
        await search.process()

    assert len(await search.get_emails()) == 50
    assert len(await search.get_hostnames()) == 50
    assert requests[-1] == 'https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=2'
    assert 'Tomba request failed with HTTP 429' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.asyncio
async def test_free_tomba_search_honors_limit_and_start(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Free'},
                    'requests': {'domains': {'available': 10, 'used': 0}},
                }
            },
            tomba_page(0, 10),
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = tombasearch.SearchTomba('example.test', 5, 3)
    await search.process()

    assert requests == [
        'https://api.tomba.io/v1/me',
        'https://api.tomba.io/v1/domain-search?domain=example.test&limit=10&page=1',
    ]
    assert set(await search.get_emails()) == {
        'user3@example.test',
        'user4@example.test',
        'user5@example.test',
        'user6@example.test',
        'user7@example.test',
    }


@pytest.mark.asyncio
async def test_paid_tomba_search_stops_before_exceeding_quota(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Growth'},
                    'requests': {'domains': {'available': 2, 'used': 0}},
                }
            },
            {'data': {'total': 120}},
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = tombasearch.SearchTomba('example.test', 120, 0)
    await search.process()

    assert requests == [
        'https://api.tomba.io/v1/me',
        'https://api.tomba.io/v1/email-count?domain=example.test',
    ]
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
