import logging
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

from theHarvester.discovery import sherlockeye
from theHarvester.discovery.constants import MissingKey


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: None)

    with pytest.raises(MissingKey):
        sherlockeye.SearchSherlockeye('example.com')


@pytest.mark.asyncio
async def test_process_extracts_domain_intelligence(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    api_payload = {
        'success': True,
        'data': {
            'searchId': 'search-1',
            'type': 'domain',
            'value': 'example.com',
            'timeoutSeconds': 60,
            'status': 'complete',
            'progress': 100,
            'results': [
                {
                    'id': 'result-1',
                    'source': 'provider-a',
                    'attributes': {
                        'domain': 'sub.example.com',
                        'email': 'user@example.com',
                        'ip': '203.0.113.10',
                        'link': 'https://www.example.com/path',
                    },
                },
                {
                    'id': 'result-2',
                    'source': 'provider-b',
                    'attributes': {
                        'email': 'other@not-example.org',
                        'link': 'https://api.example.com/docs',
                    },
                },
            ],
        },
        'balance': {'credits': 10},
    }

    class _FakeResponse:
        status = 200

        async def json(self):
            return api_payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', _FakeSession)

    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert await search.get_hostnames() == {'sub.example.com', 'example.com', 'api.example.com'}
    assert await search.get_emails() == {'user@example.com'}
    assert await search.get_ips() == {'203.0.113.10'}


@pytest.mark.asyncio
async def test_process_handles_api_error(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class _FakeResponse:
        status = 401

        async def text(self):
            return 'provider-secret-payload'

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', _FakeSession)
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_emails() == set()
    assert await search.get_ips() == set()
    assert 'provider-secret-payload' not in caplog.text
    assert '401' in caplog.text


@pytest.mark.asyncio
async def test_process_does_not_log_provider_error_message(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class _FakeResponse:
        status = 200

        async def json(self):
            return {'success': False, 'message': 'provider-secret-payload'}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', _FakeSession)
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    await sherlockeye.SearchSherlockeye('example.com').process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'API error' in caplog.text
