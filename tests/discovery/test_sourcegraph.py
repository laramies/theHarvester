import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import sourcegraph
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_sourcegraph_processes_one_bounded_current_file_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    payload = '''event: filters
data: [{"value":"type:file"}]

event: progress
data: {"done":false,"matchCount":1}

event: matches
data: [{"type":"content","repository":"github.com/example/repo","commit":"0123456789abcdef","path":"config/example.txt","lineMatches":[{"line":"API.EXAMPLE.COM admin@Example.COM outside.example.net other@example.net"}]}]

event: done
data: {}
'''

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(sourcegraph.Core, 'get_user_agent', staticmethod(lambda: 'test-agent'))
    search = sourcegraph.SearchSourcegraph('example.com', limit=750)

    await search.process(proxy=True)

    assert calls == [
        {
            'url': 'https://sourcegraph.com/.api/search/stream',
            'headers': {'Accept': 'text/event-stream', 'User-Agent': 'test-agent'},
            'params': {
                'q': '"example.com" type:file count:500 timeout:10s patternType:keyword',
                'v': 'V3',
                'cm': 'false',
            },
            'proxy': True,
            'request_timeout': 60,
            'include_metadata': True,
        }
    ]
    assert await search.get_hostnames() == ['api.example.com', 'example.com']
    assert await search.get_emails() == {'admin@example.com'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('http_status', 'execution_status', 'stop_reason'),
    [
        (401, 'failed', 'access-denied'),
        (403, 'failed', 'access-denied'),
        (429, 'rate-limited', 'http-429'),
        (503, 'failed', 'http-503'),
    ],
)
async def test_sourcegraph_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    http_status: int,
    execution_status: str,
    stop_reason: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body='provider response', status=http_status, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason
    assert await search.get_hostnames() == []
    assert await search.get_emails() == set()


@pytest.mark.asyncio
async def test_sourcegraph_attributes_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise OSError('network unavailable')

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_sourcegraph_normalizes_the_query_target(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        queries.append(kwargs['params']['q'])
        return FetcherResponse(body='event: done\ndata: {}\n', status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('Example.COM.', limit=10)

    await search.process()

    assert queries == ['"example.com" type:file count:10 timeout:10s patternType:keyword']


@pytest.mark.asyncio
async def test_sourcegraph_rejects_malformed_matches_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '''event: matches
data: {"not":"a-list"}

event: done
data: {}
'''

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
@pytest.mark.parametrize('with_result', [False, True], ids=['failed', 'partial'])
async def test_sourcegraph_error_event_is_not_overwritten_by_done(
    monkeypatch: pytest.MonkeyPatch,
    with_result: bool,
) -> None:
    matches = (
        'event: matches\ndata: [{"type":"content","lineMatches":[{"line":"api.example.com"}]}]\n\n'
        if with_result
        else ''
    )
    payload = f'{matches}event: error\ndata: {{"message":"provider failed"}}\n\nevent: done\ndata: {{}}\n'

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == ('partial' if with_result else 'failed')
    assert search.stop_reason == 'provider-error'


@pytest.mark.asyncio
async def test_sourcegraph_valid_empty_stream_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '''event: progress
data: {"done":true,"matchCount":0}

event: done
data: {}
'''

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'
    assert await search.get_hostnames() == []
    assert await search.get_emails() == set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        'event: matches\ndata: not-json\n\nevent: done\ndata: {}\n',
        'event: progress\ndata: {}\n',
    ],
    ids=['malformed-json', 'missing-done'],
)
async def test_sourcegraph_invalid_stream_fails(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_sourcegraph_preserves_results_before_malformed_event(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '''event: matches
data: [{"type":"content","lineMatches":[{"line":"api.example.com Admin@Example.COM api.example.com"}]}]

event: progress
data: not-json
'''

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=payload, status=200, headers={})

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    await search.process()

    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'
    assert await search.get_hostnames() == ['api.example.com', 'example.com']
    assert await search.get_emails() == {'admin@example.com'}


@pytest.mark.asyncio
async def test_sourcegraph_preserves_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    search = sourcegraph.SearchSourcegraph('example.com', limit=10)

    with pytest.raises(asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason', 'has_results'),
    [
        (
            FetcherResponse(
                body='event: progress\ndata: {"done":true}\n\nevent: done\ndata: {}\n',
                status=200,
                headers={},
            ),
            'completed',
            'no-results',
            False,
        ),
        (FetcherResponse(body='', status=429, headers={}), 'rate-limited', 'http-429', False),
        (FetcherResponse(body='', status=403, headers={}), 'failed', 'access-denied', False),
        (FetcherResponse(body='event: matches\ndata: not-json\n', status=200, headers={}), 'failed', 'invalid-response', False),
        (
            FetcherResponse(
                body='event: error\ndata: {"message":"provider failed"}\n\nevent: done\ndata: {}\n',
                status=200,
                headers={},
            ),
            'failed',
            'provider-error',
            False,
        ),
        (
            FetcherResponse(
                body='event: matches\ndata: [{"type":"content","lineMatches":[{"line":"api.example.com"}]}]\n\nevent: progress\ndata: not-json\n',
                status=200,
                headers={},
            ),
            'partial',
            'invalid-response',
            True,
        ),
    ],
    ids=['empty', 'rate-limited', 'access-denied', 'malformed', 'provider-error', 'partial'],
)
async def test_sourcegraph_outcomes_reach_completed_result_and_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response: FetcherResponse,
    execution_status: str,
    stop_reason: str,
    has_results: bool,
) -> None:
    completed_results: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return response

    report = tmp_path / f'sourcegraph-{execution_status}'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'sourcegraph', '-l', '10', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    execution = completed_results[0].source_executions[0]
    assert execution.source == 'sourcegraph'
    assert execution.status == execution_status
    assert execution.stop_reason == stop_reason
    assert bool(execution.result_count) is has_results
    summary = json.loads(report.with_suffix('.jsonl').read_text().splitlines()[0])
    assert summary['source_executions'][0]['status'] == execution_status
    assert summary['source_executions'][0]['stop_reason'] == stop_reason
