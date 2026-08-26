from contextlib import asynccontextmanager
from typing import Any

import pytest

from theHarvester.discovery import rocketreach
from theHarvester.discovery.constants import MissingKey


@pytest.fixture(autouse=True)
def proxy_aware_session(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    session_options: list[dict[str, Any]] = []

    @asynccontextmanager
    async def open_session(**kwargs: Any):
        session_options.append(kwargs)
        yield object()

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'open_session', open_session)
    return session_options


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
            return {
                'profiles': first_page_profiles,
                'pagination': {'page': 1, 'total': 150},
            }

        second_page_profiles = []
        for index in range(100, 150):
            second_page_profiles.append(
                {
                    'linkedin_url': f'https://linkedin.com/in/user{index}',
                    'emails': [{'email': f'user{index}@example.com'}],
                }
            )
        return {
            'profiles': second_page_profiles,
            'pagination': {'page': 2, 'total': 150},
        }

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
        return {'detail': 'Request was throttled. Credits will become available in 10 seconds.'}

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = rocketreach.SearchRocketReach('example.com', 10)
    await search.process()

    assert len(calls) == 1


pytestmark = pytest.mark.provider_contract('rocketreach')
