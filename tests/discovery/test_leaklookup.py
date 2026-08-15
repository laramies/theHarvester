import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import leaklookup
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize('key', [None, '', ' '])
def test_leaklookup_rejects_missing_or_blank_key(monkeypatch, key) -> None:
    monkeypatch.setattr(leaklookup.Core, 'leaklookup_key', lambda: key)

    with pytest.raises(MissingKey):
        leaklookup.SearchLeakLookup('example.test')


@pytest.mark.asyncio
async def test_leaklookup_posts_domain_search_and_keeps_normalized_evidence(monkeypatch) -> None:
    requests: list[tuple[str, dict[str, str], bool]] = []

    async def fake_post_fetch(url: str, *, data, proxy=False, **kwargs: Any) -> FetcherResponse:
        assert kwargs['include_metadata'] is True
        assert 'Authorization' not in kwargs['headers']
        requests.append((url, data, proxy))
        return FetcherResponse(
            body={
                'error': 'false',
                'message': {
                    'Example Breach': [
                        {
                            'email_address': 'alice@example.test',
                            'password': 'fixture-password-must-not-be-retained',
                            'ipaddress': '192.0.2.10',
                        },
                        {'email': 'bob@example.test', 'secret': 'fixture-secret-must-not-be-retained'},
                        {'email_address': 7},
                    ],
                    'Public Only Breach': {'fields': ['email_address', 'password']},
                },
            },
            status=200,
            headers={},
        )

    monkeypatch.setattr(leaklookup.Core, 'leaklookup_key', lambda: 'test-key')
    monkeypatch.setattr(leaklookup.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(leaklookup.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = leaklookup.SearchLeakLookup('example.test')

    await search.process(proxy=True)

    assert requests == [
        (
            'https://leak-lookup.com/api/search',
            {'key': 'test-key', 'type': 'domain', 'query': 'example.test'},
            True,
        )
    ]
    assert await search.get_emails() == {'alice@example.test', 'bob@example.test'}
    assert await search.get_breach_names() == {'Example Breach', 'Public Only Breach'}
    assert await search.get_sources() == {'Example Breach', 'Public Only Breach'}
    assert await search.get_leaks() == [
        {'breach': 'Example Breach', 'email': 'alice@example.test'},
        {'breach': 'Example Breach', 'email': 'bob@example.test'},
        {'breach': 'Public Only Breach'},
    ]
    assert await search.get_passwords() == set()
    assert await search.get_hostnames() == set()
    assert await search.get_leak_dates() == set()
    assert 'fixture-password' not in repr(await search.get_leaks())
    assert 'fixture-secret' not in repr(await search.get_leaks())


@pytest.mark.parametrize('status', [401, 403, 429])
@pytest.mark.asyncio
async def test_leaklookup_http_failure_returns_no_results(monkeypatch, caplog, status: int) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={'message': 'provider detail'}, status=status, headers={})

    monkeypatch.setattr(leaklookup.Core, 'leaklookup_key', lambda: 'test-key')
    monkeypatch.setattr(leaklookup.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(leaklookup.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = leaklookup.SearchLeakLookup('example.test')

    with caplog.at_level(logging.INFO, logger=leaklookup.__name__):
        await search.process()

    assert await search.get_emails() == set()
    assert await search.get_breach_names() == set()
    assert f'Leak-Lookup request failed with HTTP {status}' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.parametrize(
    ('response', 'message'),
    [
        (None, 'Leak-Lookup request failed without a response'),
        (FetcherResponse(body='not json', status=200, headers={}), 'Leak-Lookup returned malformed data'),
        (FetcherResponse(body={}, status=200, headers={}), 'Leak-Lookup returned malformed data'),
        (
            FetcherResponse(
                body={'error': 'true', 'message': 'RATE LIMIT REACHED provider detail'},
                status=200,
                headers={},
            ),
            'Leak-Lookup request failed',
        ),
    ],
)
@pytest.mark.asyncio
async def test_leaklookup_empty_or_malformed_response_fails_closed(monkeypatch, caplog, response, message) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any):
        return response

    monkeypatch.setattr(leaklookup.Core, 'leaklookup_key', lambda: 'test-key')
    monkeypatch.setattr(leaklookup.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(leaklookup.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = leaklookup.SearchLeakLookup('example.test')

    with caplog.at_level(logging.INFO, logger=leaklookup.__name__):
        await search.process()

    assert await search.get_emails() == set()
    assert await search.get_leaks() == []
    assert message in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.asyncio
async def test_leaklookup_empty_success_returns_no_results(monkeypatch) -> None:
    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={'error': 'false', 'message': {}}, status=200, headers={})

    monkeypatch.setattr(leaklookup.Core, 'leaklookup_key', lambda: 'test-key')
    monkeypatch.setattr(leaklookup.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(leaklookup.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = leaklookup.SearchLeakLookup('example.test')

    await search.process()

    assert await search.get_emails() == set()
    assert await search.get_breach_names() == set()


@pytest.mark.asyncio
async def test_leaklookup_emails_and_breaches_reach_completed_result_and_jsonl(monkeypatch, tmp_path: Path) -> None:
    completed_results: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class FakeLeakLookup:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_emails(self) -> set[str]:
            return {'alice@example.com'}

        async def get_breach_names(self) -> set[str]:
            return {'Example Breach'}

    report = tmp_path / 'leaklookup-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(leaklookup, 'SearchLeakLookup', FakeLeakLookup)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'leaklookup', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (
        ('breach', 'Example Breach'),
        ('email', 'alice@example.com'),
    )
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'breach', 'value': 'Example Breach', 'sources': ['leaklookup']} in records
    assert {'type': 'email', 'value': 'alice@example.com', 'sources': ['leaklookup']} in records
