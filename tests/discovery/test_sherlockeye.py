import asyncio
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

    aiohttp_socks_stub.ProxyConnector = _ProxyConnector  # type: ignore[attr-defined]
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import sherlockeye
from theHarvester.discovery.constants import MissingKey


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_raises(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: key)

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
                {'attributes': {'email': 'user@notexample.com'}},
                {'attributes': {'email': 'user@example.com.evil'}},
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

    assert await search.get_hostnames() == {'sub.example.com', 'www.example.com', 'api.example.com'}
    assert await search.get_emails() == {'user@example.com'}
    assert await search.get_ips() == {'203.0.113.10'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


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
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'access-denied'


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

    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'API error' in caplog.text
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'provider-error'


@pytest.mark.parametrize(
    ('status', 'execution_status', 'stop_reason'),
    [(429, 'rate-limited', 'http-429'), (503, 'failed', 'http-503')],
)
@pytest.mark.asyncio
async def test_http_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class FakeResponse:
        async def __aenter__(self):
            self.status = status
            return self

        async def __aexit__(self, *_args):
            return None

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', FakeSession)
    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_malformed_response_is_structured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class FakeResponse:
        status = 200

        async def json(self):
            return []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', FakeSession)
    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


def test_malformed_link_does_not_discard_later_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    search = sherlockeye.SearchSherlockeye('example.com')

    search._extract_response(
        {
            'success': True,
            'data': {
                'results': [
                    {'attributes': {'link': 'https://[invalid'}},
                    {'attributes': {'link': 'https://api.example.com/path'}},
                ]
            },
        }
    )

    assert search.totalhosts == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_transport_failure_and_cancellation_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class FailedSession:
        def __init__(self, **_kwargs):
            raise RuntimeError('provider-secret')

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', FailedSession)
    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'

    class CancelledSession:
        def __init__(self, **_kwargs):
            raise asyncio.CancelledError

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', CancelledSession)
    with pytest.raises(asyncio.CancelledError):
        await sherlockeye.SearchSherlockeye('example.com').process()


pytestmark = pytest.mark.provider_contract('sherlockeye')
