import asyncio
import contextlib
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import crtname, crtsh
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import ResponseStreamError


class FakeResponse:
    def __init__(
        self,
        records: tuple[str, ...],
        status: int = 200,
        error: BaseException | None = None,
    ) -> None:
        self.records = records
        self.status = status
        self.headers: dict[str, str] = {}
        self.error = error

    def __aiter__(self) -> AsyncIterator[str]:
        async def records() -> AsyncIterator[str]:
            for record in self.records:
                yield record
            if self.error is not None:
                raise self.error

        return records()


@pytest.mark.asyncio
async def test_crt_name_streams_one_provider_response_and_retains_scoped_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def stream_records(url: str, **kwargs: Any) -> AsyncIterator[FakeResponse]:
        calls.append({'url': url, **kwargs})
        yield FakeResponse(
            (
                'example.com',
                'API.Example.COM.',
                '*.wild.example.com',
                'outside.example.net',
                '',
            )
        )

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName(' Example.COM. ')

    await search.process(proxy=True)

    assert calls == [
        {
            'url': 'https://crt.name/v1/search',
            'framing': 'ndjson',
            'params': {'apex': 'example.com'},
            'headers': {'Accept': 'text/plain'},
            'proxy': True,
            'follow_redirects': False,
            'request_timeout': 90,
        }
    ]
    assert await search.get_hostnames() == {'api.example.com', 'wild.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_crt_name_queries_and_retains_only_the_requested_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def stream_records(url: str, **kwargs: Any) -> AsyncIterator[FakeResponse]:
        calls.append({'url': url, **kwargs})
        yield FakeResponse(('www.example.com', 'deep.www.example.com'))

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('www.example.com')

    await search.process()

    assert calls[0]['params'] == {'apex': 'www.example.com'}
    assert await search.get_hostnames() == {'deep.www.example.com'}
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_crt_name_queries_a_syntactically_valid_unknown_suffix_without_public_suffix_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    @contextlib.asynccontextmanager
    async def stream_records(url: str, **kwargs: Any) -> AsyncIterator[FakeResponse]:
        calls.append({'url': url, **kwargs})
        yield FakeResponse(())

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)

    await crtname.SearchCrtName('scope.example').process()

    assert calls[0]['params'] == {'apex': 'scope.example'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'execution_status', 'stop_reason'),
    [
        (400, 'failed', 'http-400'),
        (401, 'failed', 'access-denied'),
        (403, 'failed', 'access-denied'),
        (429, 'rate-limited', 'http-429'),
        (503, 'failed', 'http-503'),
    ],
)
async def test_crt_name_attributes_provider_status_without_parsing_error_bodies(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    execution_status: str,
    stop_reason: str,
) -> None:
    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse(('must-not-be-retained.example.com',), status=status)

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_crt_name_preserves_valid_prefix_when_stream_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse(('api.example.com',), error=ResponseStreamError('response-limit'))

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_crt_name_preserves_valid_prefix_at_runtime_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    class SlowResponse(FakeResponse):
        def __aiter__(self) -> AsyncIterator[str]:
            async def records() -> AsyncIterator[str]:
                yield 'api.example.com'
                await asyncio.Event().wait()

            return records()

    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield SlowResponse(())

    monkeypatch.setattr(crtname.SearchCrtName, 'RUNTIME_SECONDS', 0.01)
    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_crt_name_empty_response_completes_without_results(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse(())

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'target',
    [
        '',
        'localhost',
        'https://example.com',
        '192.0.2.1',
        '192.168.001.001',
        'example.com..',
        '\u212a.example.com',
        'straße.de',
    ],
)
async def test_crt_name_rejects_invalid_targets_without_requesting(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    def unexpected_request(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError('invalid targets must not reach crt.name')

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', unexpected_request)
    search = crtname.SearchCrtName(target)

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-target'


@pytest.mark.asyncio
async def test_crt_name_rejects_non_ascii_provider_records(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse(('\u212a.example.com', 'api.example.com'))

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    search = crtname.SearchCrtName('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_crt_name_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    cancelled = asyncio.CancelledError()

    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse((), error=cancelled)

    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)

    with pytest.raises(asyncio.CancelledError) as raised:
        await crtname.SearchCrtName('example.com').process()

    assert raised.value is cancelled


@pytest.mark.asyncio
async def test_crt_name_and_crtsh_share_one_result_with_both_sources(
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

    class FakeCrtsh:
        execution_status = 'completed'
        stop_reason = None

        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'shared.example.com'}

    @contextlib.asynccontextmanager
    async def stream_records(*_args: Any, **_kwargs: Any) -> AsyncIterator[FakeResponse]:
        yield FakeResponse(('shared.example.com', 'only-crt-name.example.com'))

    report = tmp_path / 'crt-name-overlap'
    monkeypatch.setattr(crtname.AsyncFetcher, 'stream_records', stream_records)
    monkeypatch.setattr(crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'crt-name,crtsh', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert {execution.source for execution in completed_results[-1].source_executions} == {'crt-name', 'crtsh'}
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    findings = {(record['type'], record['value']): record for record in records[1:]}
    assert findings[('hostname', 'shared.example.com')]['sources'] == ['crt-name', 'crtsh']
    assert findings[('hostname', 'only-crt-name.example.com')]['sources'] == ['crt-name']
