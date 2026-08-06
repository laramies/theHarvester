import logging
from typing import Any

import pytest

from theHarvester.discovery import hudsonrocksearch
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_rate_limited_domain_search_recovers_without_trailing_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    sleeps: list[float] = []
    responses = [
        FetcherResponse(body={'error': 'rate limited'}, status=429, headers={'retry-after': '0'}),
        FetcherResponse(
            body={'data': {'employees_urls': [{'url': 'https://portal.example.com/login'}]}},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        nonlocal calls
        calls += 1
        assert urls == ['https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=example.com']
        assert kwargs == {'json': True, 'proxy': False, 'include_metadata': True}
        return [responses.pop(0)]

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', fake_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}
    assert calls == 2
    assert sleeps == [0]


@pytest.mark.asyncio
async def test_email_search_preserves_normalized_getters(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs == {'json': True, 'proxy': False, 'include_metadata': True}
        if urls[0].endswith('search-by-domain?domain=example.com'):
            return [FetcherResponse(body={'data': {'employees_urls': []}}, status=200, headers={})]
        assert urls[0].endswith('search-by-email?email=analyst@example.com')
        return [
            FetcherResponse(
                body={
                    'stealers': [
                        {
                            'ip': '192.0.2.4',
                            'top_corporate_services': [{'domain': 'portal.example.com'}],
                            'top_user_services': [],
                        }
                    ]
                },
                status=200,
                headers={},
            )
        ]

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', fake_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}
    assert await search.get_ips() == {'192.0.2.4'}
    assert await search.get_emails() == {'analyst@example.com'}
    assert len(await search.get_infostealers()) == 1
    assert sleeps == [1.0]


@pytest.mark.asyncio
async def test_domain_search_ignores_malformed_url_items(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'data': {
                        'employees_urls': [
                            'not-an-object',
                            {'url': 'https://portal.example.com/login'},
                        ]
                    }
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}


@pytest.mark.asyncio
async def test_email_search_ignores_malformed_stealer_items(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        body = (
            {'data': {'employees_urls': []}}
            if 'search-by-domain' in urls[0]
            else {
                'stealers': [
                    'not-an-object',
                    {'ip': '192.0.2.5', 'top_corporate_services': [], 'top_user_services': []},
                ]
            }
        )
        return [FetcherResponse(body=body, status=200, headers={})]

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    await search.process()

    assert await search.get_ips() == {'192.0.2.5'}
    assert len(await search.get_infostealers()) == 1


@pytest.mark.asyncio
async def test_empty_email_search_does_not_invent_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        body = {'data': {'employees_urls': []}} if 'search-by-domain' in urls[0] else {'stealers': []}
        return [FetcherResponse(body=body, status=200, headers={})]

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert await search.get_emails() == set()
    assert await search.get_infostealers() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_log'),
    [
        (FetcherResponse(body={'error': 'forbidden'}, status=403, headers={}), 'failed with HTTP 403'),
        (FetcherResponse(body=['not-an-object'], status=200, headers={}), 'Invalid response format'),
    ],
)
async def test_terminal_domain_responses_are_attributed_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    response: FetcherResponse,
    expected_log: str,
) -> None:
    calls = 0

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        nonlocal calls
        calls += 1
        return [response]

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    with caplog.at_level(logging.INFO, logger=hudsonrocksearch.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert calls == 1
    assert expected_log in caplog.text
