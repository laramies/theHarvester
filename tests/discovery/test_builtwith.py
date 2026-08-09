import json
import sys
import types
from pathlib import Path

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
from theHarvester import __main__ as theharvester_main
from theHarvester.lib.completed_result import CompletedResult


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
            None,
            {'name': 'Django', 'category': 'framework'},
            {'name': 'Python', 'category': 'language'},
            {'name': 'nginx', 'category': 'server'},
            {'name': 'WordPress', 'category': 'cms'},
            {'name': 'Google Analytics', 'category': 'analytics'},
            {'category': 'framework'},
            {'name': ' ', 'category': 'server'},
            {'name': 7, 'category': 'cms'},
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


@pytest.mark.asyncio
async def test_normalized_builtwith_results_reach_completed_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed_results: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class FakeBuiltWith:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_interesting_urls(self) -> set[str]:
            return {'https://example.com/login'}

        async def get_frameworks(self) -> set[str]:
            return {'Django'}

        async def get_languages(self) -> set[str]:
            return {'Python'}

        async def get_servers(self) -> set[str]:
            return {'nginx'}

        async def get_cms(self) -> set[str]:
            return {'WordPress'}

        async def get_analytics(self) -> set[str]:
            return {'Google Analytics'}

    report = tmp_path / 'builtwith-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.builtwith, 'SearchBuiltWith', FakeBuiltWith)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'builtwith', '-f', str(report)])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (
        ('analytics', 'Google Analytics'),
        ('cms', 'WordPress'),
        ('framework', 'Django'),
        ('interesting-url', 'https://example.com/login'),
        ('language', 'Python'),
        ('server', 'nginx'),
    )
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'interesting-url', 'value': 'https://example.com/login', 'sources': ['builtwith']} in records
    assert {'type': 'framework', 'value': 'Django', 'sources': ['builtwith']} in records
    assert {'type': 'language', 'value': 'Python', 'sources': ['builtwith']} in records
    assert {'type': 'server', 'value': 'nginx', 'sources': ['builtwith']} in records
    assert {'type': 'cms', 'value': 'WordPress', 'sources': ['builtwith']} in records
    assert {'type': 'analytics', 'value': 'Google Analytics', 'sources': ['builtwith']} in records
