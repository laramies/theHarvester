import asyncio
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    aiohttp_socks_stub.ProxyConnector = _ProxyConnector  # type: ignore[attr-defined]
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import builtwith
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import source_runner
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse, ResponseStreamError


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: None)

    with pytest.raises(MissingKey):
        builtwith.SearchBuiltWith('example.com')


@pytest.mark.asyncio
async def test_process_uses_v23_privacy_controls_and_parses_nested_results(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')
    monkeypatch.setattr(builtwith.Core, 'get_user_agent', lambda: 'test-agent')
    api_payload = {
        'Results': [
            {
                'Lookup': 'example.com',
                'Result': {
                    'Paths': [
                        {
                            'Domain': 'example.com',
                            'SubDomain': 'api',
                            'Url': 'dd',
                            'Technologies': [
                                {'Name': 'Django', 'Tag': 'framework'},
                                {'Name': 'Python', 'Tag': 'language'},
                                {'Name': 'nginx', 'Categories': ['Web Server']},
                                {'Name': 'WordPress', 'Tag': 'cms'},
                                {'Name': 'Google Analytics', 'Categories': ['Analytics']},
                            ],
                        },
                        {
                            'Domain': 'example.com',
                            'SubDomain': '',
                            'Url': '/login',
                            'Technologies': [],
                        },
                    ]
                },
            }
        ]
    }
    captured: dict[str, Any] = {}

    async def fake_fetch_json(url: str, **kwargs: Any) -> FetcherResponse:
        captured['url'] = url
        captured.update(kwargs)
        return FetcherResponse(api_payload, 200, {})

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('example.com')
    await search.process(proxy=True)

    assert captured == {
        'url': 'https://api.builtwith.com/v23/api.json',
        'params': {
            'HIDEDL': 'yes',
            'LOOKUP': 'example.com',
            'NOATTR': 'yes',
            'NOMETA': 'yes',
            'NOPII': 'yes',
        },
        'proxy': True,
        'headers': {
            'Accept': 'application/json',
            'Authorization': 'API dummy-key',
            'User-Agent': 'test-agent',
        },
    }
    assert await search.get_hostnames() == {'api.example.com', 'example.com'}
    assert await search.get_urls() == {'https://example.com/login'}
    assert await search.get_frameworks() == {'Django'}
    assert await search.get_languages() == {'Python'}
    assert await search.get_servers() == {'nginx'}
    assert await search.get_cms() == {'WordPress'}
    assert await search.get_analytics() == {'Google Analytics'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_www_target_does_not_accept_sibling_subdomains(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')
    captured: dict[str, Any] = {}
    payload = {
        'Results': [
            {
                'Result': {
                    'Paths': [
                        {'Domain': 'example.com', 'SubDomain': 'www', 'Url': 'dd', 'Technologies': []},
                        {'Domain': 'example.com', 'SubDomain': 'api', 'Url': 'dd', 'Technologies': []},
                    ]
                }
            }
        ]
    }

    async def fake_fetch_json(*_args: Any, **kwargs: Any) -> FetcherResponse:
        captured.update(kwargs)
        return FetcherResponse(payload, 200, {})

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('www.example.com')

    await search.process()

    assert captured['params']['LOOKUP'] == 'example.com'
    assert await search.get_hostnames() == {'www.example.com'}
    assert await search.get_urls() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_named_technology_without_a_usable_category_is_malformed(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')
    payload = {
        'Results': [
            {
                'Result': {
                    'Paths': [
                        {
                            'Domain': 'example.com',
                            'SubDomain': 'www',
                            'Url': 'dd',
                            'Technologies': [{'Name': 'Unclassified Product', 'Tag': ' ', 'Categories': []}],
                        }
                    ]
                }
            }
        ]
    }

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(payload, 200, {})

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('example.com')

    await search.process()

    assert await search.get_hostnames() == {'www.example.com'}
    assert await search.get_urls() == set()
    assert await search.get_frameworks() == set()
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_status', 'expected_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(None, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse(None, 403, {}), 'failed', 'access-denied'),
        (FetcherResponse(None, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse(None, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'Results': {}}, 200, {}), 'failed', 'invalid-response'),
    ],
)
async def test_process_reports_failed_responses_truthfully(
    monkeypatch,
    response: FetcherResponse | None,
    expected_status: str,
    expected_reason: str,
) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_tech_stack() == {}
    assert search.execution_status == expected_status
    assert search.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_malformed_nested_containers_retain_accepted_evidence(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')
    payload = {
        'Results': [
            {
                'Result': {
                    'Paths': [
                        {
                            'Domain': 'example.com',
                            'SubDomain': 'api',
                            'Url': 'dd',
                            'Technologies': [
                                None,
                                {'Name': 'Django', 'Tag': 'framework'},
                                {'Name': 'nginx', 'Categories': ['Web Server', None]},
                            ],
                        },
                        {'Domain': 'outside.invalid', 'SubDomain': '', 'Url': 'dd', 'Technologies': []},
                        {'Domain': 'example.com', 'SubDomain': 7, 'Url': [], 'Technologies': {}},
                    ]
                }
            },
            None,
        ]
    }

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(payload, 200, {})

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_urls() == set()
    assert await search.get_frameworks() == {'Django'}
    assert await search.get_servers() == {'nginx'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['invalid-response', 'response-limit', 'transport-error'])
async def test_bounded_response_failures_are_attributed(monkeypatch, reason: str) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError(reason)  # type: ignore[arg-type]

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = builtwith.SearchBuiltWith('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch) -> None:
    monkeypatch.setattr(builtwith.Core, 'builtwith_key', lambda: 'dummy-key')

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(builtwith.AsyncFetcher, 'fetch_json', fake_fetch_json)

    with pytest.raises(asyncio.CancelledError):
        await builtwith.SearchBuiltWith('example.com').process()


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

        async def get_urls(self) -> set[str]:
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
    monkeypatch.setattr(source_runner.builtwith, 'SearchBuiltWith', FakeBuiltWith)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'builtwith', '-f', str(report)])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (
        ('analytics', 'Google Analytics'),
        ('cms', 'WordPress'),
        ('framework', 'Django'),
        ('language', 'Python'),
        ('server', 'nginx'),
        ('url', 'https://example.com/login'),
    )
    assert completed_results[0].source_executions[0].source == 'builtwith'
    assert completed_results[0].source_executions[0].status == 'completed'
    assert completed_results[0].source_executions[0].result_count == 6
    assert {observation.source for observation in completed_results[0].observations} == {'builtwith'}
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'url', 'value': 'https://example.com/login', 'sources': ['builtwith']} in records
    assert {'type': 'framework', 'value': 'Django', 'sources': ['builtwith']} in records
    assert {'type': 'language', 'value': 'Python', 'sources': ['builtwith']} in records
    assert {'type': 'server', 'value': 'nginx', 'sources': ['builtwith']} in records
    assert {'type': 'cms', 'value': 'WordPress', 'sources': ['builtwith']} in records
    assert {'type': 'analytics', 'value': 'Google Analytics', 'sources': ['builtwith']} in records
