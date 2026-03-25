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
    """BuiltWith API returns 'text/json' content-type; response.json(content_type=None)
    must be used so aiohttp does not raise a ContentTypeError."""
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

    class _FakeResponse:
        status = 200

        async def json(self, **kwargs):
            # Simulate aiohttp accepting content_type=None for 'text/json' responses
            assert kwargs.get('content_type') is None, (
                'content_type=None must be passed to accept non-standard MIME types like text/json'
            )
            return api_payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def get(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(builtwith.aiohttp, 'ClientSession', _FakeSession)

    search = builtwith.SearchBuiltWith('example.com')
    await search.process()

    assert await search.get_hostnames() == {'sub.example.com'}
    assert await search.get_interesting_urls() == {'https://example.com/login'}
    assert await search.get_frameworks() == {'Django'}
    assert await search.get_languages() == {'Python'}
    assert await search.get_servers() == {'nginx'}
    assert await search.get_cms() == {'WordPress'}
    assert await search.get_analytics() == {'Google Analytics'}


@pytest.mark.asyncio
async def test_process_handles_non_200_status(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    class _FakeResponse:
        status = 403

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def get(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(builtwith.aiohttp, 'ClientSession', _FakeSession)

    search = builtwith.SearchBuiltWith('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_tech_stack() == {}
