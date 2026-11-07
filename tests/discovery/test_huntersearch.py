import logging
from typing import Any

import pytest

from theHarvester.discovery import huntersearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.parametrize('key', [None, '  '])
def test_hunter_rejects_missing_or_blank_key(monkeypatch, key) -> None:
    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: key)

    with pytest.raises(MissingKey):
        huntersearch.SearchHunter('example.test', 10, 0)


@pytest.mark.parametrize(
    ('status', 'expected_report'),
    [
        (401, SourceExecutionReport('failed', 'access-denied')),
        (403, SourceExecutionReport('failed', 'access-denied')),
        (429, SourceExecutionReport('rate-limited', 'http-429')),
    ],
)
@pytest.mark.asyncio
async def test_hunter_http_failures_return_no_results(monkeypatch, caplog, status: int, expected_report) -> None:
    async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'error': 'provider detail'}, status=status, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = huntersearch.SearchHunter('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=huntersearch.__name__):
        report = await search.process()

    assert report == expected_report
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []

    assert f'Hunter request failed with HTTP {status}' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.parametrize(
    ('response', 'message', 'expected_report'),
    [
        ([], 'Hunter request failed without a response', SourceExecutionReport('failed', 'transport-error')),
        ([None], 'Hunter request failed without a response', SourceExecutionReport('failed', 'transport-error')),
        (
            [FetcherResponse(body='not json', status=200, headers={})],
            'Hunter returned malformed data',
            SourceExecutionReport('failed', 'invalid-response'),
        ),
        (
            [FetcherResponse(body={}, status=200, headers={})],
            'Hunter returned malformed data',
            SourceExecutionReport('failed', 'invalid-response'),
        ),
    ],
)
@pytest.mark.asyncio
async def test_hunter_empty_or_malformed_response_returns_no_results(
    monkeypatch, caplog, response, message, expected_report
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any):
        return response

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = huntersearch.SearchHunter('example.test', 10, 0)

    with caplog.at_level(logging.INFO, logger=huntersearch.__name__):
        report = await search.process()

    assert report == expected_report
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert message in caplog.text


@pytest.mark.asyncio
async def test_paid_hunter_search_honors_limit_and_offset(monkeypatch) -> None:
    import contextlib

    requests: list[tuple[str, object]] = []
    session_proxy: list[object] = []
    session = object()

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any):
        session_proxy.append(kwargs.get('proxy'))
        yield session

    responses = iter(
        [
            {'data': {'plan_name': 'Growth', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {'data': {'total': 175}},
            {
                'data': {
                    'emails': [
                        {'value': 'alice@example.test', 'sources': [{'domain': 'api.example.test'}]},
                    ]
                }
            },
            {
                'data': {
                    'emails': [
                        {'value': 'bob@example.test', 'sources': [{'domain': 'www.example.test'}]},
                    ]
                }
            },
        ]
    )

    async def fake_fetch_all(urls, *, session=None, **_kwargs):
        requests.append((urls[0], session))
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(huntersearch.asyncio, 'sleep', no_sleep)

    search = huntersearch.SearchHunter('example.test', 150, 25)
    await search.process(proxy=True)

    assert session_proxy == [True]
    assert all(entry[1] is session for entry in requests)
    assert [entry[0] for entry in requests] == [
        'https://api.hunter.io/v2/account?api_key=test-key',
        'https://api.hunter.io/v2/email-count?domain=example.test',
        'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=100&offset=25',
        'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=50&offset=125',
    ]
    assert await search.get_emails() == ['alice@example.test', 'bob@example.test']
    assert await search.get_hostnames() == ['api.example.test', 'www.example.test']


@pytest.mark.asyncio
async def test_paid_hunter_search_preserves_first_page_after_rate_limit(monkeypatch, caplog) -> None:
    requests: list[str] = []
    responses = iter(
        [
            FetcherResponse(
                body={'data': {'plan_name': 'Growth', 'requests': {'searches': {'available': 10, 'used': 0}}}},
                status=200,
                headers={},
            ),
            FetcherResponse(body={'data': {'total': 175}}, status=200, headers={}),
            FetcherResponse(
                body={
                    'data': {
                        'emails': [
                            {'value': 'alice@example.test', 'sources': [{'domain': 'api.example.test'}]},
                        ]
                    }
                },
                status=200,
                headers={},
            ),
            FetcherResponse(body={'error': 'provider detail'}, status=429, headers={}),
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [next(responses)]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(huntersearch.asyncio, 'sleep', no_sleep)
    search = huntersearch.SearchHunter('example.test', 150, 0)

    with caplog.at_level(logging.INFO, logger=huntersearch.__name__):
        report = await search.process()

    assert report == SourceExecutionReport('rate-limited', 'http-429')
    assert await search.get_emails() == ['alice@example.test']
    assert await search.get_hostnames() == ['api.example.test']
    assert requests[-1].endswith('limit=50&offset=100')
    assert 'Hunter request failed with HTTP 429' in caplog.text
    assert 'provider detail' not in caplog.text


@pytest.mark.asyncio
async def test_free_hunter_search_honors_limit_and_offset(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {'data': {'plan_name': 'Free', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {'data': {'emails': []}},
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', 5, 3)
    await search.process()

    assert requests == [
        'https://api.hunter.io/v2/account?api_key=test-key',
        'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=5&offset=3',
    ]


@pytest.mark.asyncio
async def test_free_hunter_unlimited_reports_saturated_provider_boundary(monkeypatch) -> None:
    responses = iter(
        [
            {'data': {'plan_name': 'Free', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {
                'data': {
                    'emails': [
                        {'value': f'user{index}@example.test', 'sources': [{'domain': f'user{index}.example.test'}]}
                        for index in range(10)
                    ]
                }
            },
        ]
    )

    async def fake_fetch_all(*_args, **_kwargs):
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', None, 0)

    assert await search.process() == SourceExecutionReport('partial', 'provider-limit')
    assert len(await search.get_hostnames()) == 10


@pytest.mark.asyncio
async def test_free_hunter_search_rejects_out_of_scope_source_domains(monkeypatch) -> None:
    responses = iter(
        [
            {'data': {'plan_name': 'Free', 'requests': {'searches': {'available': 10, 'used': 0}}}},
            {
                'data': {
                    'emails': [
                        {
                            'value': 'alice@example.test',
                            'sources': [
                                {'domain': 'api.example.test'},
                                {'domain': 'notexample.test'},
                                {'domain': 'example.test.evil.net'},
                            ],
                        },
                    ]
                }
            },
        ]
    )

    async def fake_fetch_all(*_args, **_kwargs):
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', 10, 0)
    await search.process()

    assert await search.get_emails() == ['alice@example.test']
    assert await search.get_hostnames() == ['api.example.test']


@pytest.mark.asyncio
async def test_paid_hunter_search_stops_before_exceeding_quota(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {'data': {'plan_name': 'Growth', 'requests': {'searches': {'available': 1, 'used': 0}}}},
            {'data': {'total': 250}},
            {
                'data': {
                    'emails': [
                        {'value': 'alice@example.test', 'sources': [{'domain': 'api.example.test'}]},
                    ]
                }
            },
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [FetcherResponse(body=next(responses), status=200, headers={})]

    monkeypatch.setattr(huntersearch.Core, 'hunter_key', lambda: 'test-key')
    monkeypatch.setattr(huntersearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(huntersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = huntersearch.SearchHunter('example.test', 250, 0)
    report = await search.process()

    assert requests == [
        'https://api.hunter.io/v2/account?api_key=test-key',
        'https://api.hunter.io/v2/email-count?domain=example.test',
        'https://api.hunter.io/v2/domain-search?domain=example.test&api_key=test-key&limit=100&offset=0',
    ]
    assert report == SourceExecutionReport('partial', 'quota-exhausted')
    assert await search.get_emails() == ['alice@example.test']
    assert await search.get_hostnames() == ['api.example.test']


pytestmark = pytest.mark.provider_contract('hunter')
