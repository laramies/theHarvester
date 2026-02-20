import sys
import types

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    aiohttp_socks_stub.ProxyConnector = _ProxyConnector
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import rocketreach
from theHarvester.discovery.constants import MissingKey


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: None)
    with pytest.raises(MissingKey):
        rocketreach.SearchRocketReach('example.com', 10)


@pytest.mark.asyncio
async def test_do_search_uses_people_data_endpoint_and_start_pagination(monkeypatch) -> None:
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
    await search.process()

    assert len(calls) == 2
    first_url, first_headers, first_data, first_json, _ = calls[0]
    second_url, _, second_data, _, _ = calls[1]

    assert first_url == 'https://api.rocketreach.co/api/v2/person/search'
    assert second_url == 'https://api.rocketreach.co/api/v2/person/search'
    assert first_headers['Api-Key'] == 'test-key'
    assert first_headers['User-Agent'] == 'test-agent'
    assert first_json is True
    assert first_data == {'query': {'current_employer_domain': ['example.com']}, 'start': 0, 'page_size': 100}
    assert second_data == {'query': {'current_employer_domain': ['example.com']}, 'start': 100, 'page_size': 50}

    links = await search.get_links()
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
