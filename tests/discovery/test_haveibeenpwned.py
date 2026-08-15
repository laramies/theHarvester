import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import haveibeenpwned
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse


def test_public_breach_catalog_does_not_require_api_key() -> None:
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    assert 'hibp-api-key' not in search.headers


@pytest.mark.asyncio
async def test_public_breach_catalog_preserves_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://haveibeenpwned.com/api/v3/breaches?domain=example.com']
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return [
            FetcherResponse(
                body=[
                    {
                        'Name': 'ExampleBreach',
                        'Domain': 'example.com',
                        'BreachDate': '2024-01-02',
                        'DataClasses': ['Email addresses', 'Passwords'],
                    }
                ],
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_hostnames() == {'example.com'}
    assert await search.get_breach_names() == {'ExampleBreach'}
    assert await search.get_breach_dates() == {'2024-01-02'}
    assert await search.get_affected_data() == {'Email addresses', 'Passwords'}
    assert await search.get_emails() == set()
    assert await search.get_pastes() == []
    assert await search.get_breach_types() == set()
    assert await search.get_breaches() == [
        {
            'Name': 'ExampleBreach',
            'Domain': 'example.com',
            'BreachDate': '2024-01-02',
            'DataClasses': ['Email addresses', 'Passwords'],
        }
    ]


@pytest.mark.asyncio
async def test_public_breach_catalog_ignores_blank_names(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=[{'Name': '  '}, {'Name': 'ExampleBreach'}], status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_breach_names() == {'ExampleBreach'}


@pytest.mark.asyncio
async def test_public_breach_catalog_valid_empty_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=[], status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_breaches() == []
    assert await search.get_hostnames() == set()
    assert await search.get_breach_dates() == set()
    assert await search.get_affected_data() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('http_status', 'execution_status'),
    [(429, 'rate-limited'), (503, 'failed')],
)
async def test_public_breach_catalog_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    http_status: int,
    execution_status: str,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'provider failure'}, status=http_status, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    with caplog.at_level(logging.INFO, logger=haveibeenpwned.__name__):
        await search.process()

    assert await search.get_breaches() == []
    assert f'HaveIBeenPwned request failed with HTTP {http_status}' in caplog.text
    assert search.execution_status == execution_status
    assert search.stop_reason == f'http-{http_status}'


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [None, {}, ['not-a-breach']])
async def test_public_breach_catalog_malformed_json_fails(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'
    assert await search.get_breaches() == []


@pytest.mark.asyncio
async def test_public_breach_catalog_missing_metadata_is_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[None]:
        return [None]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process(proxy=True)

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_public_breach_catalog_preserves_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    with pytest.raises(asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
async def test_public_breach_names_reach_completed_result_and_jsonl(
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

    class FakeHaveIBeenPwned:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_breach_names(self) -> set[str]:
            return {'Adobe', 'ExampleBreach'}

    report = tmp_path / 'hibp-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(haveibeenpwned, 'SearchHaveIBeenPwned', FakeHaveIBeenPwned)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'haveibeenpwned', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (
        ('breach', 'Adobe'),
        ('breach', 'ExampleBreach'),
    )
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'breach', 'value': 'Adobe', 'sources': ['haveibeenpwned']} in records
    assert {'type': 'breach', 'value': 'ExampleBreach', 'sources': ['haveibeenpwned']} in records
