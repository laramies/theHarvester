import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester.discovery import haveibeenpwned
from theHarvester import __main__ as theharvester_main
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
@pytest.mark.parametrize('payload', [[], None, {}, ['not-a-breach']])
async def test_public_breach_catalog_handles_empty_and_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_breaches() == []
    assert await search.get_hostnames() == set()
    assert await search.get_breach_dates() == set()
    assert await search.get_affected_data() == set()


@pytest.mark.asyncio
async def test_public_breach_catalog_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'rate limited'}, status=429, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    with caplog.at_level(logging.INFO, logger=haveibeenpwned.__name__):
        await search.process()

    assert await search.get_breaches() == []
    assert 'HaveIBeenPwned request failed with HTTP 429' in caplog.text


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
    monkeypatch.setattr(theharvester_main.haveibeenpwned, 'SearchHaveIBeenPwned', FakeHaveIBeenPwned)
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
