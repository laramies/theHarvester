from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import sourcegraph

if TYPE_CHECKING:
    from pathlib import Path

    from theHarvester.lib.completed_result import CompletedResult


def event(name: str, payload: object) -> str:
    return f'event: {name}\ndata: {json.dumps(payload)}'


def install_stream(
    monkeypatch: pytest.MonkeyPatch,
    records: tuple[str, ...] = (),
    *,
    status: int = 200,
    error: BaseException | None = None,
    allow_reserved_target: bool = True,
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    if allow_reserved_target:
        monkeypatch.setattr(
            sourcegraph,
            '_SPECIAL_USE_SUFFIXES',
            sourcegraph._SPECIAL_USE_SUFFIXES - {'test'},
        )

    class FakeResponse:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict[str, str] = {}

        async def __aiter__(self):
            for record in records:
                yield record
            if error is not None:
                raise error

    @contextlib.asynccontextmanager
    async def fake_stream_records(url: str, **kwargs: Any):
        calls.append({'url': url, **kwargs})
        if error is not None and not records:
            raise error
        yield FakeResponse()

    async def buffered_fetch_is_not_the_sourcegraph_seam(**_kwargs: Any):
        raise AssertionError('Sourcegraph must use AsyncFetcher.stream_records')

    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'stream_records', fake_stream_records)
    monkeypatch.setattr(sourcegraph.AsyncFetcher, 'fetch', buffered_fetch_is_not_the_sourcegraph_seam)
    return calls


@pytest.mark.asyncio
async def test_sourcegraph_uses_fixed_chunk_query_and_collects_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = (
        event('filters', [{'value': 'type:file'}]),
        event(
            'matches',
            [
                {
                    'type': 'content',
                    'repository': 'example.invalid/repo',
                    'path': 'config.json',
                    'chunkMatches': [
                        {
                            'content': (
                                'API.SCOPE.TEST. deep.api.scope.test scope.test '
                                '*.wild.scope.test outside.invalid 192.0.2.1 '
                                'münchen.scope.test api.scope.testé bad.scope.test....'
                            ),
                            'ranges': [],
                        },
                        {'content': 'api.scope.test', 'ranges': []},
                    ],
                },
                {'type': 'path', 'path': 'ignored.scope.test'},
            ],
        ),
        event('progress', {'done': True, 'matchCount': 2, 'skipped': []}),
        event('done', {}),
    )
    calls = install_stream(monkeypatch, records)
    search = sourcegraph.SearchSourcegraph(' Scope.TEST. ', limit=1)

    await search.process(proxy=True)

    assert calls == [
        {
            'url': 'https://sourcegraph.com/.api/search/stream',
            'framing': 'sse',
            'headers': {'Accept': 'text/event-stream'},
            'params': {
                'q': '"scope.test" type:file count:5000 timeout:10s patternType:keyword',
                'v': 'V3',
                'cm': 'true',
                'cl': 0,
                'max-line-len': 4096,
                'display': 5000,
            },
            'proxy': True,
            'follow_redirects': False,
            'request_timeout': 60,
        }
    ]
    assert await search.get_hostnames() == ['api.scope.test', 'deep.api.scope.test']
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'target',
    [
        '',
        '.',
        'localhost',
        'not a domain',
        '-bad.example',
        '192.0.2.1',
        '192.168.001.001',
        'scope.test" count:all',
        'straße.de',
        '\u212a.scope.test',
        'www.example.com',
        'scope.test....',
        '.'.join(['9' * 100] * 4),
        'service.test',
        'service.local',
    ],
)
async def test_sourcegraph_rejects_unsafe_targets_before_request(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    calls = install_stream(monkeypatch, allow_reserved_target=False)
    search = sourcegraph.SearchSourcegraph(target, limit=500)

    await search.process()

    assert calls == []
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-target'
    assert await search.get_hostnames() == []


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
    install_stream(monkeypatch, status=http_status)
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['transport-error', 'invalid-response', 'response-limit'])
async def test_sourcegraph_attributes_stream_failures(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    install_stream(monkeypatch, error=sourcegraph.ResponseStreamError(reason))
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_sourcegraph_preserves_hosts_before_stream_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    records = (
        event(
            'matches',
            [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test', 'ranges': []}]}],
        ),
    )
    install_stream(
        monkeypatch,
        records,
        error=sourcegraph.ResponseStreamError('response-limit'),
    )
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert await search.get_hostnames() == ['api.scope.test']
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'response-limit'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'bad_record',
    [
        'event: matches\ndata: not-json',
        event('matches', {'not': 'a-list'}),
        event('matches', [{'type': 'content', 'chunkMatches': 'not-a-list'}]),
        event('matches', [{'type': 'content', 'chunkMatches': [{'content': 7}]}]),
        event('unknown', {}),
        'event: done\ndata: {}\nrogue: ignored',
        'event: done\ndata: {}\ndata: {}',
    ],
)
async def test_sourcegraph_rejects_malformed_provider_events(
    monkeypatch: pytest.MonkeyPatch,
    bad_record: str,
) -> None:
    install_stream(monkeypatch, (bad_record, event('done', {})))
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'records',
    [
        (event('progress', {'done': True, 'skipped': []}),),
        (event('progress', {'done': False, 'skipped': []}), event('done', {})),
        (event('done', {}),),
    ],
    ids=['missing-done', 'nonterminal-progress', 'missing-progress'],
)
async def test_sourcegraph_requires_terminal_progress_and_done(
    monkeypatch: pytest.MonkeyPatch,
    records: tuple[str, ...],
) -> None:
    install_stream(monkeypatch, records)
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
@pytest.mark.parametrize('with_host', [False, True], ids=['failed', 'partial'])
async def test_sourcegraph_attributes_provider_error(
    monkeypatch: pytest.MonkeyPatch,
    with_host: bool,
) -> None:
    records = []
    if with_host:
        records.append(
            event(
                'matches',
                [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test'}]}],
            )
        )
    records.append(event('error', {'message': 'search failed'}))
    install_stream(monkeypatch, tuple(records))
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == ('partial' if with_host else 'failed')
    assert search.stop_reason == 'provider-error'


@pytest.mark.asyncio
async def test_sourcegraph_final_skipped_progress_marks_provider_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = (
        event(
            'matches',
            [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test'}]}],
        ),
        event('progress', {'done': True, 'skipped': [{'reason': 'shard-match-limit'}]}),
        event('done', {}),
    )
    install_stream(monkeypatch, records)
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert await search.get_hostnames() == ['api.scope.test']
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'provider-limited'


@pytest.mark.asyncio
async def test_sourcegraph_uses_only_the_final_progress_skipped_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_stream(
        monkeypatch,
        (
            event('progress', {'done': False, 'skipped': [{'reason': 'shard-match-limit'}]}),
            event('progress', {'done': False, 'skipped': []}),
            event('progress', {'done': True, 'skipped': []}),
            event('done', {}),
        ),
    )
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_sourcegraph_rejects_match_after_terminal_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stream(
        monkeypatch,
        (
            event('progress', {'done': True, 'skipped': []}),
            event('matches', [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test'}]}]),
            event('done', {}),
        ),
    )
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_sourcegraph_rejects_events_after_done(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stream(monkeypatch, (event('done', {}), event('progress', {'done': True})))
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_sourcegraph_preserves_prefix_at_hostname_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stream(
        monkeypatch,
        (
            event(
                'matches',
                [
                    {
                        'type': 'content',
                        'chunkMatches': [{'content': 'one.scope.test two.scope.test'}],
                    }
                ],
            ),
            event('progress', {'done': True, 'skipped': []}),
            event('done', {}),
        ),
    )
    monkeypatch.setattr(sourcegraph.SearchSourcegraph, 'MAX_HOSTNAMES', 1)
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert await search.get_hostnames() == ['one.scope.test']
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_sourcegraph_preserves_prefix_at_event_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stream(
        monkeypatch,
        (
            event(
                'matches',
                [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test'}]}],
            ),
            event('progress', {'done': False, 'skipped': []}),
        ),
    )
    monkeypatch.setattr(sourcegraph.SearchSourcegraph, 'MAX_EVENTS', 1)
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert await search.get_hostnames() == ['api.scope.test']
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_sourcegraph_treats_deep_json_as_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    nested = '[' * 2_000 + ']' * 2_000
    install_stream(monkeypatch, (f'event: alert\ndata: {nested}',))
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_sourcegraph_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stream(monkeypatch, error=asyncio.CancelledError())
    search = sourcegraph.SearchSourcegraph('scope.test', limit=500)

    with pytest.raises(asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
async def test_sourcegraph_partial_outcome_reaches_completed_result(
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

    install_stream(
        monkeypatch,
        (
            event(
                'matches',
                [{'type': 'content', 'chunkMatches': [{'content': 'api.scope.test'}]}],
            ),
            event('progress', {'done': True, 'skipped': [{'reason': 'shard-match-limit'}]}),
            event('done', {}),
        ),
    )
    report = tmp_path / 'sourcegraph-partial'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'scope.test', '-b', 'sourcegraph', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    execution = completed_results[0].source_executions[0]
    assert execution.source == 'sourcegraph'
    assert execution.status == 'partial'
    assert execution.stop_reason == 'provider-limited'
    assert execution.result_count == 1
    summary = json.loads(report.with_suffix('.jsonl').read_text().splitlines()[0])
    assert summary['source_executions'][0]['stop_reason'] == 'provider-limited'
