from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import TYPE_CHECKING, Any
from unittest.mock import ANY, AsyncMock

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import hudsonrocksearch
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from pathlib import Path

    from theHarvester.lib.completed_result import CompletedResult


@pytest.mark.asyncio
async def test_rate_limited_domain_search_recovers_without_trailing_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    sleeps: list[float] = []
    responses = [
        FetcherResponse(body={'error': 'rate limited'}, status=429, headers={'retry-after': '0'}),
        FetcherResponse(
            body={'data': {'employees_urls': [{'url': 'https://portal.example.com/login'}]}},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        nonlocal calls
        calls += 1
        assert urls == ['https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=example.com']
        assert kwargs == {'json': True, 'session': ANY, 'include_metadata': True}
        return [responses.pop(0)]

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', fake_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}
    assert calls == 2
    assert sleeps == [0]
    assert report is None


@pytest.mark.asyncio
async def test_email_search_preserves_normalized_getters(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs == {'json': True, 'session': ANY, 'include_metadata': True}
        if urls[0].endswith('search-by-domain?domain=example.com'):
            return [FetcherResponse(body={'data': {'employees_urls': []}}, status=200, headers={})]
        assert urls[0].endswith('search-by-email?email=analyst@example.com')
        return [
            FetcherResponse(
                body={
                    'stealers': [
                        {
                            'ip': '192.0.2.4',
                            'top_corporate_services': [{'domain': 'portal.example.com'}],
                            'top_user_services': [],
                        }
                    ]
                },
                status=200,
                headers={},
            )
        ]

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', fake_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}
    assert await search.get_ips() == {'192.0.2.4'}
    assert await search.get_emails() == {'analyst@example.com'}
    assert len(await search.get_infostealers()) == 1
    assert sleeps == [1.0]
    assert report is None


@pytest.mark.asyncio
async def test_domain_search_ignores_malformed_url_items(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'data': {
                        'employees_urls': [
                            'not-an-object',
                            {'url': 7},
                            {'url': 'https://portal.example.com/login'},
                        ]
                    }
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'portal.example.com'}
    assert report == SourceExecutionReport('partial', 'invalid-response')


@pytest.mark.asyncio
async def test_email_search_ignores_malformed_stealer_items(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        body = (
            {'data': {'employees_urls': []}}
            if 'search-by-domain' in urls[0]
            else {
                'stealers': [
                    'not-an-object',
                    {'top_corporate_services': None},
                    {'ip': '192.0.2.5', 'top_corporate_services': [], 'top_user_services': []},
                ]
            }
        )
        return [FetcherResponse(body=body, status=200, headers={})]

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    report = await search.process()

    assert await search.get_ips() == {'192.0.2.5'}
    assert len(await search.get_infostealers()) == 1
    assert report == SourceExecutionReport('partial', 'invalid-response')


@pytest.mark.asyncio
async def test_empty_email_search_does_not_invent_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        body = {'data': {'employees_urls': []}} if 'search-by-domain' in urls[0] else {'stealers': []}
        return [FetcherResponse(body=body, status=200, headers={})]

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert await search.get_emails() == set()
    assert await search.get_infostealers() == []
    assert report is None


@pytest.mark.asyncio
async def test_email_search_retains_domain_results_when_email_request_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock()
    build_session = AsyncMock(return_value=session)
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, '_build_session', build_session)
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, '_resolve_proxy', lambda proxy: ('http://proxy.example:8080', 'http'))

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        assert _kwargs['session'] is session and 'proxy' not in _kwargs
        if 'search-by-domain' in urls[0]:
            return [FetcherResponse({'data': {'employees_urls': [{'url': 'https://portal.example.com/login'}]}}, 200, {})]
        return [FetcherResponse({}, 503, {})]

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('analyst@example.com')

    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'portal.example.com'}
    assert report == SourceExecutionReport('partial', 'http-503')
    build_session.assert_awaited_once_with(ANY, ANY, 'http://proxy.example:8080', 'http', ANY, None)
    assert build_session.call_args.args[1].total == 60
    session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_search_transport_failure_and_cancellation_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failed(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise OSError('provider-secret')

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', failed)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', no_sleep)
    assert await hudsonrocksearch.SearchHudsonRock('example.com').process() == SourceExecutionReport('failed', 'transport-error')

    async def cancelled(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', cancelled)
    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await hudsonrocksearch.SearchHudsonRock('analyst@example.com').process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'expected_log', 'expected_report'),
    [
        (
            FetcherResponse(body={'error': 'forbidden'}, status=403, headers={}),
            'failed with HTTP 403',
            SourceExecutionReport('failed', 'access-denied'),
        ),
        (
            FetcherResponse(body=['not-an-object'], status=200, headers={}),
            'Invalid response format',
            SourceExecutionReport('failed', 'invalid-response'),
        ),
    ],
)
async def test_terminal_domain_responses_are_attributed_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    response: FetcherResponse,
    expected_log: str,
    expected_report: SourceExecutionReport,
) -> None:
    calls = 0

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        nonlocal calls
        calls += 1
        return [response]

    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    with caplog.at_level(logging.INFO, logger=hudsonrocksearch.__name__):
        report = await search.process()

    assert await search.get_hostnames() == set()
    assert calls == 1
    assert expected_log in caplog.text
    assert report == expected_report


@pytest.mark.asyncio
async def test_infostealer_data_reaches_completed_result_and_jsonl(
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

    class FakeHudsonRock:
        def __init__(self, target: str) -> None:
            assert target == 'analyst@example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_emails(self) -> set[str]:
            return {'analyst@example.com'}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.4'}

        async def get_infostealers(self) -> list[dict[str, object]]:
            return [
                {
                    'email': 'analyst@example.com',
                    'computer_name': 'WORKSTATION-1',
                    'ip': '192.0.2.4',
                    'top_corporate_services': ['portal.example.com'],
                }
            ]

    report = tmp_path / 'hudsonrock-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(hudsonrocksearch, 'SearchHudsonRock', FakeHudsonRock)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'analyst@example.com', '-b', 'hudsonrock', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    stealer = (
        '{"computer_name":"WORKSTATION-1","email":"analyst@example.com","ip":"192.0.2.4",'
        '"top_corporate_services":["portal.example.com"]}'
    )
    assert ('infostealer', stealer) in completed_results[0].results
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'infostealer', 'value': stealer, 'sources': ['hudsonrock']} in records


pytestmark = pytest.mark.provider_contract('hudsonrock')
