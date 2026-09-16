import asyncio
from contextlib import asynccontextmanager
from typing import Any

import pytest

from theHarvester.discovery import rocketreach
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.fixture(autouse=True)
def proxy_aware_session(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    session_options: list[dict[str, Any]] = []

    @asynccontextmanager
    async def open_session(**kwargs: Any):
        session_options.append(kwargs)
        try:
            yield object()
        finally:
            kwargs['closed'] = True

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'open_session', open_session)
    yield session_options
    assert all(options.get('closed') for options in session_options)


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: None)
    with pytest.raises(MissingKey):
        rocketreach.SearchRocketReach('example.com', 10)


@pytest.mark.asyncio
async def test_do_search_uses_people_data_endpoint_and_start_pagination(
    monkeypatch: pytest.MonkeyPatch,
    proxy_aware_session: list[dict[str, Any]],
) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')
    monkeypatch.setattr(rocketreach.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(rocketreach, 'get_delay', lambda: 0)

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr(rocketreach.asyncio, 'sleep', fake_sleep)

    calls = []

    async def fake_post_fetch(url, headers=None, data=None, json=False, **kwargs):
        calls.append((url, headers, data, json, kwargs))
        if len(calls) == 1:
            first_page_profiles = []
            for index in range(100):
                first_page_profiles.append(
                    {
                        'linkedin_url': f'https://linkedin.com/in/user{index}',
                        'emails': [{'email': f'user{index}@example.com'}],
                    }
                )
            return FetcherResponse({'profiles': first_page_profiles, 'pagination': {'page': 1, 'total': 150}}, 200, {})

        second_page_profiles = []
        for index in range(100, 150):
            second_page_profiles.append(
                {
                    'linkedin_url': f'https://linkedin.com/in/user{index}',
                    'emails': [{'email': f'user{index}@example.com'}],
                }
            )
        return FetcherResponse({'profiles': second_page_profiles, 'pagination': {'page': 2, 'total': 150}}, 200, {})

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = rocketreach.SearchRocketReach('example.com', 150)
    await search.process(proxy=True)

    assert len(calls) == 2
    first_url, first_headers, first_data, first_json, first_kwargs = calls[0]
    second_url, _, second_data, _, second_kwargs = calls[1]

    assert first_url == 'https://api.rocketreach.co/api/v2/person/search'
    assert second_url == 'https://api.rocketreach.co/api/v2/person/search'
    assert first_headers['Api-Key'] == 'test-key'
    assert first_headers['User-Agent'] == 'test-agent'
    assert first_json is True
    assert first_kwargs['include_metadata'] is True
    assert first_data == {'query': {'current_employer_domain': ['example.com']}, 'start': 0, 'page_size': 100}
    assert second_data == {'query': {'current_employer_domain': ['example.com']}, 'start': 100, 'page_size': 50}
    assert first_kwargs['session'] is second_kwargs['session']
    assert len(proxy_aware_session) == 1
    assert proxy_aware_session[0]['proxy'] is True

    links = await search.get_urls()
    emails = await search.get_emails()
    assert len(links) == 150
    assert len(emails) == 150
    assert 'https://linkedin.com/in/user0' in links
    assert 'https://linkedin.com/in/user149' in links
    assert 'user0@example.com' in emails
    assert 'user149@example.com' in emails


@pytest.mark.asyncio
async def test_do_search_stops_on_throttling_message(monkeypatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')
    monkeypatch.setattr(rocketreach.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(rocketreach, 'get_delay', lambda: 0)

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr(rocketreach.asyncio, 'sleep', fake_sleep)

    calls = []

    async def fake_post_fetch(url, headers=None, data=None, json=False, **kwargs):
        calls.append((url, data))
        return FetcherResponse({'detail': 'Request was throttled. Credits will become available in 10 seconds.'}, 200, {})

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = rocketreach.SearchRocketReach('example.com', 10)
    report = await search.process()

    assert len(calls) == 1
    assert report == SourceExecutionReport('rate-limited', 'provider-rate-limit')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected'),
    [
        (None, SourceExecutionReport('failed', 'transport-error')),
        (FetcherResponse({}, 403, {}), SourceExecutionReport('failed', 'access-denied')),
        (FetcherResponse({}, 429, {}), SourceExecutionReport('rate-limited', 'http-429')),
        (FetcherResponse('not-json', 200, {}), SourceExecutionReport('failed', 'invalid-response')),
        (FetcherResponse({'profiles': []}, 200, {}), None),
    ],
)
async def test_search_reports_terminal_outcomes(monkeypatch, response, expected) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')
    monkeypatch.setattr(rocketreach.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(rocketreach, 'get_delay', lambda: -5)

    async def fake_post_fetch(*_args, **kwargs):
        assert kwargs['include_metadata'] is True
        return response

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(rocketreach.asyncio, 'sleep', no_sleep)

    assert await rocketreach.SearchRocketReach('example.com', 10).process() == expected


@pytest.mark.asyncio
async def test_search_retains_first_page_when_later_page_is_rate_limited(monkeypatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')
    monkeypatch.setattr(rocketreach.Core, 'get_user_agent', lambda: 'test-agent')
    profiles = [
        {'linkedin_url': f'https://linkedin.com/in/user{index}', 'emails': [{'email': f'user{index}@example.com'}]}
        for index in range(100)
    ]
    responses = [
        FetcherResponse({'profiles': profiles, 'pagination': {'total': 150}}, 200, {}),
        FetcherResponse({}, 429, {}),
    ]

    async def fake_post_fetch(*_args, **_kwargs):
        return responses.pop(0)

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = rocketreach.SearchRocketReach('example.com', 150)

    report = await search.process()

    assert report == SourceExecutionReport('partial', 'http-429')
    assert len(await search.get_emails()) == 100
    assert len(await search.get_urls()) == 100


@pytest.mark.asyncio
async def test_search_cancellation_propagates(monkeypatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')

    async def cancelled(*_args, **_kwargs):
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', cancelled)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await rocketreach.SearchRocketReach('example.com', 10).process(proxy=True)


pytestmark = pytest.mark.provider_contract('rocketreach')
