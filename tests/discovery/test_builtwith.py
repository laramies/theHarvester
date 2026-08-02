import json
import sys
import types

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    setattr(aiohttp_socks_stub, 'ProxyConnector', _ProxyConnector)
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import builtwith
from theHarvester.discovery.constants import MissingKey


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: None)

    with pytest.raises(MissingKey):
        builtwith.SearchBuiltWith('example.com')


@pytest.mark.asyncio
async def test_process_accepts_text_json_content_type(monkeypatch) -> None:
    """BuiltWith text/json payloads must be decoded without MIME enforcement."""
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    api_payload = {
        'domains': ['sub.example.com'],
        'paths': ['https://example.com/login'],
        'technologies': [
            {'name': 'Django', 'category': 'framework'},
            {'name': 'Python', 'category': 'language'},
            {'name': 'nginx', 'category': 'server'},
            {'name': 'WordPress', 'category': 'cms'},
            {'name': 'Google Analytics', 'category': 'analytics'},
        ],
    }

    async def fake_fetch(**kwargs):
        assert kwargs['json'] is False
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        return json.dumps(api_payload)

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch', fake_fetch)

    search = builtwith.SearchBuiltWith('example.com')
    await search.process(proxy=True)

    assert await search.get_hostnames() == {'sub.example.com'}
    assert await search.get_interestingurls() == {'https://example.com/login'}
    assert await search.get_interesting_urls() == {'https://example.com/login'}
    assert await search.get_frameworks() == {'Django'}
    assert await search.get_languages() == {'Python'}
    assert await search.get_servers() == {'nginx'}
    assert await search.get_cms() == {'WordPress'}
    assert await search.get_analytics() == {'Google Analytics'}


@pytest.mark.asyncio
async def test_process_reports_non_200_status(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch(**_kwargs):
        raise RuntimeError('HTTP 403')

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch', fake_fetch)

    search = builtwith.SearchBuiltWith('example.com')
    with pytest.raises(RuntimeError, match='BuiltWith returned HTTP 403'):
        await search.process()


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', ['', '{"error": "unauthorized"}'])
async def test_proxy_failure_is_not_reported_as_empty(monkeypatch, payload) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch(**kwargs):
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['json'] is False
        return payload

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch', fake_fetch)

    search = builtwith.SearchBuiltWith('example.com')
    with pytest.raises(ValueError, match='BuiltWith returned an invalid payload'):
        await search.process(proxy=True)


@pytest.mark.asyncio
async def test_malformed_payload_is_not_reported_as_empty(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch(**_kwargs):
        return '[]'

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch', fake_fetch)

    search = builtwith.SearchBuiltWith('example.com')
    with pytest.raises(ValueError, match='BuiltWith returned an invalid payload'):
        await search.process()
