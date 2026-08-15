import json
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import hibpverified
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize('api_key', [None, '', '   '])
def test_verified_domain_source_requires_its_api_key(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str | None,
) -> None:
    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: api_key)

    with pytest.raises(MissingKey, match='HIBP verified domain'):
        hibpverified.SearchHibpVerified('example.com')


def test_verified_domain_source_handles_existing_config_without_new_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hibpverified.Core, 'api_keys', lambda: {})

    with pytest.raises(MissingKey, match='HIBP verified domain'):
        hibpverified.SearchHibpVerified('example.com')


@pytest.mark.asyncio
async def test_verified_domain_source_returns_emails_and_stable_breach_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://haveibeenpwned.com/api/v3/breachedDomain/example.com']
        assert kwargs['headers']['hibp-api-key'] == 'secret'
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return [
            FetcherResponse(
                body={
                    'alice': ['ExampleBreachA', 'ExampleBreachB'],
                    'bob': ['ExampleBreach'],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: 'secret')
    monkeypatch.setattr(hibpverified.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hibpverified.SearchHibpVerified('example.com')

    await search.process()

    assert await search.get_emails() == {'alice@example.com', 'bob@example.com'}
    assert await search.get_breach_names() == {'ExampleBreach', 'ExampleBreachA', 'ExampleBreachB'}


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [None, [], {'alice': 'ExampleBreach'}, {'': ['ExampleBreach']}, {'alice': [None]}])
async def test_verified_domain_source_rejects_malformed_responses(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: 'secret')
    monkeypatch.setattr(hibpverified.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hibpverified.SearchHibpVerified('example.com')

    await search.process()

    assert await search.get_emails() == set()
    assert await search.get_breach_names() == set()


@pytest.mark.asyncio
async def test_verified_domain_source_attributes_unverified_domain(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'statusCode': 403}, status=403, headers={})]

    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: 'secret')
    monkeypatch.setattr(hibpverified.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hibpverified.SearchHibpVerified('example.com')

    with caplog.at_level('INFO', logger=hibpverified.__name__):
        await search.process()

    assert 'HIBP verified-domain target is not verified for this API key (HTTP 403)' in caplog.text


@pytest.mark.asyncio
async def test_verified_domain_source_treats_not_found_as_valid_empty(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'statusCode': 404}, status=404, headers={})]

    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: 'secret')
    monkeypatch.setattr(hibpverified.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hibpverified.SearchHibpVerified('example.com')

    with caplog.at_level('INFO', logger=hibpverified.__name__):
        await search.process()

    assert await search.get_emails() == set()
    assert await search.get_breach_names() == set()
    assert 'failed' not in caplog.text


@pytest.mark.asyncio
async def test_verified_domain_source_attributes_rate_limit_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls = 0

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        nonlocal calls
        calls += 1
        return [FetcherResponse(body={'statusCode': 429}, status=429, headers={})]

    monkeypatch.setattr(hibpverified.Core, 'hibpverified_key', lambda: 'secret')
    monkeypatch.setattr(hibpverified.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = hibpverified.SearchHibpVerified('example.com')

    with caplog.at_level('INFO', logger=hibpverified.__name__):
        await search.process()

    assert calls == 1
    assert 'HIBP verified-domain request was rate limited (HTTP 429)' in caplog.text


@pytest.mark.asyncio
async def test_verified_domain_results_reach_completed_jsonl_and_sqlite_handoff(
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

    class FakeHibpVerified:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_emails(self) -> set[str]:
            return {'alice@example.com'}

        async def get_breach_names(self) -> set[str]:
            return {'ExampleBreach'}

    report = tmp_path / 'hibp-verified-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(hibpverified, 'SearchHibpVerified', FakeHibpVerified)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'hibpverified', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (
        ('breach', 'ExampleBreach'),
        ('email', 'alice@example.com'),
    )
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'breach', 'value': 'ExampleBreach', 'sources': ['hibpverified']} in records
    assert {'type': 'email', 'value': 'alice@example.com', 'sources': ['hibpverified']} in records
