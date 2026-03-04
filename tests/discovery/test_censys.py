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

from theHarvester.discovery import censysearch
from theHarvester.discovery.constants import MissingKey


class _FakeQuery:
    def __init__(self, pages):
        self.pages = pages

    def __iter__(self):
        return iter(self.pages)


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: (None, None))

    with pytest.raises(MissingKey):
        censysearch.SearchCensys('example.com')


@pytest.mark.asyncio
async def test_search_uses_documented_pagination_and_fields(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('id', 'secret'))

    calls = {}

    class _FakeCensysCerts:
        def __init__(self, api_id, api_secret, user_agent):
            calls['init'] = {'api_id': api_id, 'api_secret': api_secret, 'user_agent': user_agent}

        def search(self, **kwargs):
            calls['search'] = kwargs
            return _FakeQuery(
                [
                    [
                        {'names': ['a.example.com'], 'parsed': {'subject': {'email_address': 'admin@example.com'}}},
                        {'names': ['b.example.com'], 'parsed': {'subject': {'email_address': ['ops@example.com']}}},
                    ],
                    [
                        {'names': ['c.example.com'], 'parsed': {'subject': {'email_address': None}}},
                    ],
                ]
            )

    monkeypatch.setattr(censysearch, 'CensysCerts', _FakeCensysCerts)

    search = censysearch.SearchCensys('example.com', limit=250)
    await search.process()

    assert calls['init']['api_id'] == 'id'
    assert calls['init']['api_secret'] == 'secret'
    assert calls['search']['query'] == 'names: example.com'
    assert calls['search']['per_page'] == 100
    assert calls['search']['pages'] == 3
    assert calls['search']['fields'] == ['names', 'parsed.subject.email_address']
    assert await search.get_hostnames() == {'a.example.com', 'b.example.com', 'c.example.com'}
    assert await search.get_emails() == {'admin@example.com', 'ops@example.com'}


@pytest.mark.asyncio
async def test_search_respects_limit_across_page_data(monkeypatch) -> None:
    monkeypatch.setattr(censysearch.Core, 'censys_key', lambda: ('id', 'secret'))

    class _FakeCensysCerts:
        def __init__(self, api_id, api_secret, user_agent):
            del api_id, api_secret, user_agent

        def search(self, **kwargs):
            del kwargs
            return _FakeQuery(
                [
                    [
                        {'names': ['1.example.com']},
                        {'names': ['2.example.com']},
                        {'names': ['3.example.com']},
                        {'names': ['4.example.com']},
                        {'names': ['5.example.com']},
                    ]
                ]
            )

    monkeypatch.setattr(censysearch, 'CensysCerts', _FakeCensysCerts)

    search = censysearch.SearchCensys('example.com', limit=3)
    await search.process()

    assert await search.get_hostnames() == {'1.example.com', '2.example.com', '3.example.com'}
