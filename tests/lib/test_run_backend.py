from __future__ import annotations

import asyncio
import inspect
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from tests.runtime_helpers import runtime_with_process_factory, static_runtime


class _FakeScreenshotBatch:
    async def reachable_targets(self, targets: list[str]) -> list[tuple[str, str]]:
        reachable: list[tuple[str, str]] = []
        for subject in targets:
            final_url, status = await self.visit(subject)
            if status:
                reachable.append((subject, final_url))
        return reachable

    async def capture_targets(self, targets, record) -> None:
        async def capture(subject: str, final_url: str) -> tuple[str, str, Path]:
            output_path = self.screenshot_path(subject)
            return subject, await self.take_screenshot(final_url, output_path=output_path), output_path

        tasks = [asyncio.create_task(capture(*target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await record(*await task)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    await record(*outcome)
            raise
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def test_run_paths_use_one_expanded_database_and_artifact_root(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('THEHARVESTER_RUN_DB', '~/state/runs.sqlite')
    monkeypatch.delenv('THEHARVESTER_RUN_ARTIFACTS', raising=False)

    store = RunStore()

    assert store.database == tmp_path / 'state' / 'runs.sqlite'
    assert store.artifact_directory('run-id') == tmp_path / 'state' / 'run-artifacts' / 'run-id'


def test_run_store_does_not_change_caller_owned_directory_permissions(tmp_path) -> None:
    from theHarvester.lib.api.run_store import RunStore

    tmp_path.chmod(0o755)
    asyncio.run(RunStore(tmp_path / 'runs.sqlite').initialize())

    assert os.stat(tmp_path).st_mode & 0o777 == 0o755


def test_run_history_is_bounded_without_loading_completed_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    async def fail_load(*_args, **_kwargs):
        raise AssertionError('run summaries must not hydrate terminal evidence')

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        for index in range(4):
            await store.create(RunRequest(target=f'{index}.example.test', sources=['crtsh']))
        monkeypatch.setattr(store.results, 'load_run', fail_load)
        return await store.list_runs(limit=2, offset=1)

    history = asyncio.run(scenario())

    assert len(history) == 2
    assert [run['target'] for run in history] == ['2.example.test', '1.example.test']
    assert all(run['result_count'] == 0 for run in history)


def test_run_history_breaks_timestamp_ties_by_run_id(tmp_path) -> None:
    from theHarvester.lib.database import RunLifecycleStore

    async def scenario() -> list[str]:
        store = RunLifecycleStore(tmp_path / 'runs.sqlite')
        await store.initialize()
        for run_id in ('run-a', 'run-c', 'run-b'):
            await store.create(
                run_id=run_id,
                target='example.test',
                status='completed',
                origin='imported',
                created_at='2026-08-09T12:00:00+00:00',
                request_json='{}',
            )
        first = await store.list_records(limit=2, offset=0)
        second = await store.list_records(limit=2, offset=2)
        return [str(run['run_id']) for run in first + second]

    assert asyncio.run(scenario()) == ['run-c', 'run-b', 'run-a']


def test_api_lifespan_disposes_shared_sqlite_engines(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    disposed = False

    async def dispose() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(api, 'dispose_sqlite_databases', dispose)

    with TestClient(api.app):
        pass

    assert disposed is True


def test_api_lifespan_disposes_schedule_sqlite_engines(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    disposed = False

    async def dispose() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(api, 'dispose_schedule_databases', dispose)

    with TestClient(api.app):
        pass

    assert disposed is True


def test_static_assets_are_resolved_from_the_installed_module(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.chdir(tmp_path)

    assert api.STATIC_DIRECTORY == Path(api.__file__).resolve().parent / 'static'


def test_explicit_run_database_keeps_screenshot_artifacts_attached(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.delenv('THEHARVESTER_RUN_DB', raising=False)
    monkeypatch.delenv('THEHARVESTER_RUN_ARTIFACTS', raising=False)

    async def scenario():
        store = RunStore(tmp_path / 'state' / 'runs.sqlite')
        imported = await store.import_evidence(
            {
                'run_id': '4a6e5a15-fae5-462c-a34b-122ced6bb86d',
                'target': 'example.test',
                'status': 'complete',
                'started_at': '2026-08-09T12:00:00+00:00',
                'completed_at': '2026-08-09T12:01:00+00:00',
                'results': [{'type': 'hostname', 'value': 'owned.example.test', 'actions': []}],
                'source_executions': [],
                'action_executions': [
                    {
                        'action': 'screenshot',
                        'status': 'completed',
                        'duration_ms': 1,
                        'result_count': 0,
                        'error_type': None,
                        'stop_reason': None,
                    }
                ],
                'artifacts': [
                    {
                        'action': 'screenshot',
                        'kind': 'screenshot',
                        'subject': {'kind': 'hostname', 'value': 'owned.example.test'},
                        'file': {
                            'path': 'screenshots/owned.example.test.png',
                            'media_type': 'image/png',
                            'size_bytes': 3,
                            'sha256': '0' * 64,
                        },
                        'created_at': '2026-08-09T12:01:00+00:00',
                    }
                ],
            },
            'evidence.jsonl',
        )
        screenshot_dir = store.artifact_directory(imported['run_id']) / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        (screenshot_dir / 'owned.example.test.png').write_bytes(b'png')
        return await store.get(imported['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['evidence']['run_id'] == run['run_id']
    assert run['request']['source_run_id'] == '4a6e5a15-fae5-462c-a34b-122ced6bb86d'
    assert [screenshot['name'] for screenshot in run['screenshots']] == ['owned.example.test.png']


def test_api_lifecycle_and_terminal_evidence_share_the_sqlalchemy_database(tmp_path) -> None:
    from theHarvester.lib.api import run_store as run_store_module
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    database = tmp_path / 'stash.sqlite'

    async def scenario() -> str:
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh']))
        await store.claim_next()
        await store.finish(
            queued['run_id'],
            {
                'run_id': '4a6e5a15-fae5-462c-a34b-122ced6bb86d',
                'target': 'example.test',
                'status': 'complete',
                'started_at': '2026-08-09T12:00:00+00:00',
                'completed_at': '2026-08-09T12:01:00+00:00',
                'results': [{'type': 'hostname', 'value': 'api.example.test', 'sources': ['crtsh']}],
                'source_executions': [
                    {
                        'source': 'crtsh',
                        'status': 'completed',
                        'duration_ms': 1,
                        'result_count': 1,
                        'error_type': None,
                        'stop_reason': None,
                    }
                ],
            },
            '',
        )
        return queued['run_id']

    lifecycle_run_id = asyncio.run(scenario())

    with sqlite3.connect(database) as db:
        evidence_run_id = db.execute(
            'SELECT evidence_run_id FROM run_records WHERE run_id = ?',
            (lifecycle_run_id,),
        ).fetchone()[0]
        stored_target = db.execute('SELECT target FROM runs WHERE run_id = ?', (evidence_run_id,)).fetchone()[0]
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert evidence_run_id == lifecycle_run_id
    assert stored_target == 'example.test'
    assert schema_version == 8
    assert 'import aiosqlite' not in inspect.getsource(run_store_module)


def test_run_store_distinguishes_no_evidence_from_a_broken_evidence_link(tmp_path) -> None:
    from uuid import uuid4

    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.database import ResultStoreError

    database = tmp_path / 'runs.sqlite'
    store = RunStore(database)
    queued = asyncio.run(store.create(RunRequest(target='example.test', sources=['crtsh'])))
    assert asyncio.run(store.load_completed_result(queued['run_id'])) is None

    with sqlite3.connect(database) as db:
        db.execute(
            'UPDATE run_records SET evidence_run_id = ? WHERE run_id = ?',
            (str(uuid4()), queued['run_id']),
        )

    with pytest.raises(ResultStoreError, match='Attached run evidence does not exist'):
        asyncio.run(store.load_completed_result(queued['run_id']))


def test_child_execution_passes_the_configured_database_to_core(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute
    from theHarvester.lib.completed_result import CompletedResult

    database = tmp_path / 'state' / 'runs.sqlite'
    seen_database = None
    seen_run_id = None

    async def fake_start(_args, **kwargs):
        nonlocal seen_database, seen_run_id
        seen_database = kwargs.get('result_database')
        seen_run_id = kwargs.get('completed_run_id')
        now = datetime.now(UTC)
        result = CompletedResult.finish(
            run_id=seen_run_id,
            target='example.test',
            started_at=now,
            completed_at=now,
            groups={},
        )
        return (result,)

    async def scenario() -> None:
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh']))
        await store.claim_next()
        monkeypatch.setattr(main_module, 'start', fake_start)
        await _child_execute(queued['run_id'], database)

    asyncio.run(scenario())

    assert seen_database == database
    with sqlite3.connect(database) as db:
        lifecycle_run_id = db.execute('SELECT run_id FROM run_records').fetchone()[0]
    assert str(seen_run_id) == lifecycle_run_id


def test_child_screenshot_run_persists_downloadable_artifact_metadata(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api.run_artifacts import read_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            captured_url = url if url.startswith('https://') else f'https://{url}'
            (output_path or self.screenshot_path(captured_url)).write_bytes(b'png')
            return captured_url

    database = tmp_path / 'state' / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(main_module, 'ScreenShotter', FakeScreenShotter)

    async def scenario():
        store = RunStore(database)
        queued = await store.create(RunRequest(target='api.example.test', sources=[], screenshot=True))
        await store.claim_next()
        await _child_execute(queued['run_id'], database)
        evidence, error = read_child_evidence(store.artifact_directory(queued['run_id']))
        assert error is None
        assert evidence is not None
        await store.finish(queued['run_id'], evidence, '')
        return await store.get(queued['run_id']), store.artifact_directory(queued['run_id'])

    run, artifact_dir = asyncio.run(scenario())

    assert run is not None
    assert run['action_executions'][0]['action'] == 'screenshot'
    assert run['action_executions'][0]['status'] == 'completed'
    assert run['results'] == [{'type': 'hostname', 'value': 'api.example.test', 'sources': [], 'actions': []}]
    assert [screenshot['name'] for screenshot in run['screenshots']] == ['api.example.test.png']
    assert (artifact_dir / 'screenshots' / 'api.example.test.png').read_bytes() == b'png'


def test_child_screenshot_cancellation_reuses_the_checkpointed_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib import source_runner
    from theHarvester.lib.api.run_artifacts import read_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute

    first_captured = asyncio.Event()

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            assert output_path is not None
            if 'first.' in url:
                output_path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory screenshot fixture
                first_captured.set()
                return url
            await first_captured.wait()
            raise asyncio.CancelledError

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

    class TwoHostSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'first.example.test', 'second.example.test'}

    database = tmp_path / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', TwoHostSource)
    monkeypatch.setattr(main_module, 'ScreenShotter', FakeScreenShotter)

    async def scenario():
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh'], screenshot=True))
        await store.claim_next()
        await _child_execute(queued['run_id'], database)
        evidence, error = read_child_evidence(store.artifact_directory(queued['run_id']))
        assert error is None
        assert evidence is not None
        await store.fail(queued['run_id'], 'cancelled', '', cancelled=True, evidence=evidence)
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'cancelled'
    assert run['action_executions'][0]['status'] == 'partial'
    assert [screenshot['target'] for screenshot in run['screenshots']] == ['first.example.test']


def test_sqlite_import_preserves_run_ids_and_is_idempotent(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_store
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult
    from theHarvester.lib.database import ResultStore, dispose_sqlite_databases

    source_database = tmp_path / 'source.sqlite'
    destination_database = tmp_path / 'destination.sqlite'
    now = datetime.now(UTC)
    first = CompletedResult.finish(
        target='first.example.test',
        started_at=now,
        completed_at=now,
        groups={'hostname': ['api.first.example.test']},
    )
    second = CompletedResult.finish(
        target='second.example.test',
        started_at=now,
        completed_at=now,
        groups={'email': ['security@second.example.test']},
    )
    list_calls: list[tuple[int | None, int]] = []
    original_list_runs = ResultStore.list_runs

    async def track_source_batches(self, *, limit=50, offset=0):
        if Path(self.database) == source_database.resolve():
            list_calls.append((limit, offset))
        return await original_list_runs(self, limit=limit, offset=offset)

    monkeypatch.setattr(run_store, 'DATABASE_IMPORT_BATCH_SIZE', 1)
    monkeypatch.setattr(ResultStore, 'list_runs', track_source_batches)

    async def scenario():
        source = ResultStore(source_database)
        await source.initialize()
        await source.save_run(first)
        await source.save_run(second)
        await dispose_sqlite_databases()
        destination = RunStore(destination_database)
        imported = await destination.import_database(source_database, 'source.sqlite')
        first_import_calls = list(list_calls)
        list_calls.clear()
        repeated = await destination.import_database(source_database, 'source.sqlite')
        history = await destination.list_runs()
        return imported, repeated, history, first_import_calls

    imported, repeated, history, first_import_calls = asyncio.run(scenario())

    expected_ids = sorted((str(first.run_id), str(second.run_id)))
    assert imported == {'filename': 'source.sqlite', 'imported_run_ids': expected_ids, 'skipped_run_ids': []}
    assert repeated == {'filename': 'source.sqlite', 'imported_run_ids': [], 'skipped_run_ids': expected_ids}
    assert sorted(run['run_id'] for run in history) == expected_ids
    assert first_import_calls == [(1, 0), (1, 1), (1, 2), (1, 0), (1, 1), (1, 2)]


def test_orphan_recovery_reattaches_partial_checkpoint_and_leaves_queued_work(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_artifacts import ensure_private_directory, write_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = RunStore()
        for target in ('first.example', 'second.example', 'third.example'):
            await store.create(RunRequest(target=target, sources=['crtsh']))
        cancelling = await store.claim_next()
        assert cancelling is not None
        await store.cancel(cancelling['run_id'])
        artifact_dir = store.artifact_directory(cancelling['run_id'])
        ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        checkpoint = CompletedResult.finish(
            target='first.example',
            started_at=now,
            completed_at=now,
            groups={'email': ['saved@first.example']},
        )
        write_child_evidence(artifact_dir, checkpoint, partial=True)
        running = await store.claim_next()
        assert running is not None
        persisted = CompletedResult.finish(
            run_id=UUID(running['run_id']),
            target=str(running['target']),
            started_at=now,
            completed_at=now,
            groups={'hostname': [f'api.{running["target"]}']},
        )
        await store.results.save_run(persisted)
        await store.recover_orphans()
        return await store.get(cancelling['run_id']), await store.get(running['run_id']), await store.list_runs()

    cancelling, running, history = asyncio.run(scenario())

    assert cancelling is not None
    assert cancelling['status'] == 'failed'
    assert cancelling['evidence_status'] == 'partial'
    assert cancelling['results'] == [{'type': 'email', 'value': 'saved@first.example', 'sources': [], 'actions': []}]
    assert running is not None
    assert running['status'] == 'failed'
    assert running['results'] == [{'type': 'hostname', 'value': f'api.{running["target"]}', 'sources': [], 'actions': []}]
    assert {run['target']: run['status'] for run in history}['third.example'] == 'queued'


def test_orphan_recovery_prefers_immutable_persisted_evidence_over_a_newer_checkpoint(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_artifacts import ensure_private_directory, write_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example.test', sources=['crtsh']))
        claimed = await store.claim_next()
        assert claimed is not None
        await store.cancel(queued['run_id'])
        now = datetime.now(UTC)
        await store.results.save_run(
            CompletedResult.finish(
                run_id=UUID(queued['run_id']),
                target='expected.example.test',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['persisted.expected.example.test']},
            )
        )
        artifact_dir = store.artifact_directory(queued['run_id'])
        ensure_private_directory(artifact_dir)
        write_child_evidence(
            artifact_dir,
            CompletedResult.finish(
                target='expected.example.test',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['checkpoint.expected.example.test']},
            ),
            partial=True,
        )

        await store.recover_orphans()
        return await store.get(queued['run_id'])

    recovered = asyncio.run(scenario())

    assert recovered is not None
    assert recovered['status'] == 'failed'
    assert recovered['evidence_status'] == 'complete'
    assert recovered['results'] == [
        {'type': 'hostname', 'value': 'persisted.expected.example.test', 'sources': [], 'actions': []}
    ]


def test_orphan_recovery_does_not_attach_same_id_evidence_for_another_target(tmp_path) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        now = datetime.now(UTC)
        await store.results.save_run(
            CompletedResult.finish(
                run_id=UUID(queued['run_id']),
                target='different.example',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['api.different.example']},
            )
        )
        await store.recover_orphans()
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'failed'
    assert run['results'] == []


def test_orphan_recovery_rejects_checkpoint_for_another_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_artifacts import ensure_private_directory, write_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        artifact_dir = store.artifact_directory(queued['run_id'])
        ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        write_child_evidence(
            artifact_dir,
            CompletedResult.finish(
                target='different.example',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['api.different.example']},
            ),
            partial=True,
        )
        await store.recover_orphans()
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'failed'
    assert run['results'] == []
    assert 'does not match run target' in run['error']


@pytest.mark.parametrize('operation', ['finish', 'fail'])
def test_terminal_run_rejects_evidence_for_another_target(tmp_path, operation) -> None:
    from fastapi import HTTPException

    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        now = datetime.now(UTC)
        evidence = CompletedResult.finish(
            target='different.example',
            started_at=now,
            completed_at=now,
            groups={'hostname': ['api.different.example']},
        ).evidence_dict()
        terminal = (
            store.finish(queued['run_id'], evidence, '')
            if operation == 'finish'
            else store.fail(queued['run_id'], 'failed', '', evidence=evidence)
        )
        with pytest.raises(HTTPException, match='Evidence target does not match run target'):
            await terminal
        with pytest.raises(LookupError):
            await store.results.load_run(UUID(queued['run_id']))

    asyncio.run(scenario())


def test_existing_evidence_does_not_bypass_checkpoint_target_validation(tmp_path) -> None:
    from fastapi import HTTPException

    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example.test', sources=['crtsh']))
        await store.claim_next()
        now = datetime.now(UTC)
        await store.results.save_run(
            CompletedResult.finish(
                run_id=UUID(queued['run_id']),
                target='expected.example.test',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['persisted.expected.example.test']},
            )
        )
        evidence = CompletedResult.finish(
            target='different.example.test',
            started_at=now,
            completed_at=now,
            groups={},
        ).evidence_dict()
        with pytest.raises(HTTPException, match='Evidence target does not match run target'):
            await store.fail(queued['run_id'], 'failed', '', evidence=evidence)

    asyncio.run(scenario())


@pytest.mark.parametrize(('operation', 'expected_status'), [('finish', 'cancelled'), ('fail', 'failed')])
def test_terminal_run_without_checkpoint_attaches_existing_evidence(tmp_path, operation, expected_status) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example.test', sources=['crtsh']))
        await store.claim_next()
        await store.cancel(queued['run_id'])
        now = datetime.now(UTC)
        await store.results.save_run(
            CompletedResult.finish(
                run_id=UUID(queued['run_id']),
                target='expected.example.test',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['persisted.expected.example.test']},
            )
        )
        if operation == 'finish':
            await store.finish(queued['run_id'], None, '')
        else:
            await store.fail(queued['run_id'], 'failed', '')
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == expected_status
    assert run['evidence_status'] == 'complete'
    assert run['results'] == [{'type': 'hostname', 'value': 'persisted.expected.example.test', 'sources': [], 'actions': []}]


def test_worker_lease_serializes_execution_owners(tmp_path) -> None:
    from theHarvester.lib.api.run_store import RunStore

    async def scenario() -> tuple[bool, bool, bool]:
        store = RunStore(tmp_path / 'runs.sqlite')
        first = await store.acquire_worker_lease('worker-a')
        second = await store.acquire_worker_lease('worker-b')
        await store.release_worker_lease('worker-a')
        replacement = await store.acquire_worker_lease('worker-b')
        return first, second, replacement

    assert asyncio.run(scenario()) == (True, False, True)


def test_submission_fails_closed_when_worker_supervisor_stops(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    application = api.create_app(runtime_factory=lambda: static_runtime(enabled=True, available=False))

    with TestClient(application) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['crtsh']},
        )
        history = client.get('/api/v1/runs', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 503
    assert response.json()['detail'] == 'theHarvester execution worker is unavailable'
    assert history.json() == []


def test_authenticated_operator_can_queue_direct_activity_for_selected_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    application = api.create_app(runtime_factory=static_runtime)

    with TestClient(application) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': '192.0.2.8', 'sources': ['criminalip']},
        )

    assert response.status_code == 201
    assert response.json()['target'] == '192.0.2.8'
    assert response.json()['activities'] == ['P2']


def test_authenticated_operator_can_queue_screenshot_only_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    application = api.create_app(runtime_factory=static_runtime)

    with TestClient(application) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'api.example.com', 'sources': [], 'screenshot': True},
        )

    assert response.status_code == 201
    assert response.json()['target'] == 'api.example.com'
    assert response.json()['sources'] == []
    assert response.json()['activities'] == ['P2']


def test_authenticated_operator_can_queue_routeviews_only_ip_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    application = api.create_app(runtime_factory=static_runtime)

    with TestClient(application) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': '192.0.2.7', 'sources': [], 'routeviews': True},
        )

    assert response.status_code == 201
    assert response.json()['activities'] == ['P0']
    assert response.json()['request']['routeviews'] is True


def test_dns_brute_run_accepts_operator_resolver_list(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    application = api.create_app(runtime_factory=static_runtime)

    with TestClient(application) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={
                'target': 'dev.api.example.com',
                'sources': [],
                'dns_brute': True,
                'dns_resolvers': ['192.0.2.53'],
            },
        )

    assert response.status_code == 201
    assert response.json()['activities'] == ['P1']
    assert response.json()['request']['dns_resolvers'] == ['192.0.2.53']


def test_dns_brute_child_uses_operator_resolver_list(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='dev.api.example.com',
                sources=[],
                dns_brute=True,
                dns_resolvers=['192.0.2.53'],
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == ''
    assert received_options[0].dns_brute is True
    assert received_options[0].dns_resolve == ''
    assert received_options[0].dns_resolvers == ('192.0.2.53',)


def test_routeviews_child_receives_explicit_action_without_source_limit_controls(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='192.0.2.7', sources=[], routeviews=True, limit=9_999))
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == ''
    assert received_options[0].routeviews is True
    assert received_options[0].limit == 9_999


def test_persisted_unlimited_result_limit_becomes_no_worker_cap(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='example.test', sources=['crtsh'], limit=0))
        assert created['request']['limit'] == 0
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].limit is None


@pytest.mark.parametrize(
    ('field', 'value', 'option'),
    [
        ('shodan', True, '--shodan'),
        ('dns_resolve', True, '--dns-resolve'),
        ('dns_lookup', True, '--dns-lookup'),
        ('dns_brute', True, '--dns-brute'),
        ('dns_recursive_depth', 1, '--dns-recursive-depth'),
        ('takeover', True, '--take-over'),
        ('screenshot', True, '--screenshot'),
        ('vhost', True, '--vhost'),
    ],
)
def test_no_hosts_rejects_hostname_dependent_actions(field: str, value: object, option: str) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match=rf'--no-hosts cannot be combined with: {option}'):
        RunRequest(target='example.test', sources=['bufferoverun'], no_hosts=True, **{field: value})


def test_no_hosts_allows_target_only_api_scan() -> None:
    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(target='example.test', sources=[], no_hosts=True, api_scan=True)

    assert request.no_hosts is True
    assert request.api_scan is True


def test_no_hosts_conflict_precedes_virtual_host_input_validation() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match=r'--no-hosts cannot be combined with: --vhost'):
        RunRequest(target='example.test', sources=[], no_hosts=True, vhost=True)


def test_no_hosts_child_preserves_the_run_request(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='example.test', sources=['bufferoverun'], no_hosts=True))
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == 'bufferoverun'
    assert received_options[0].no_hosts is True


def test_virtual_host_request_normalizes_a_self_contained_target_action() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(
        target='Example.Test.',
        sources=[],
        vhost_endpoint='https://192.0.2.8',
        vhost_candidates=['ADMIN.Example.Test.'],
    )

    assert request.vhost is True
    assert request.vhost_endpoint == 'https://192.0.2.8:443/'
    assert request.vhost_candidates == ['admin.example.test']
    assert (
        RunRequest(
            target='example.test',
            sources=['crtsh'],
            vhost_endpoint='http://192.0.2.9',
        ).vhost
        is True
    )
    assert (
        RunRequest(
            target='example.test',
            sources=['crtsh'],
            vhost_candidates=['admin.example.test'],
        ).vhost
        is True
    )
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost_endpoint='https://192.0.2.8')
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost_candidates=['admin.example.test'])
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost=True)
    with pytest.raises(ValidationError, match='hostname target'):
        RunRequest(target='192.0.2.8', sources=['crtsh'], vhost=True)
    with pytest.raises(ValidationError, match='direct transport'):
        RunRequest(target='example.test', sources=['crtsh'], vhost=True, proxies=True)


def test_virtual_host_child_receives_bounded_controls_and_persistence_identity(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    captured = None
    captured_database = None
    captured_run_id = None

    async def fake_start(options, **kwargs):
        nonlocal captured, captured_database, captured_run_id
        captured = options
        captured_database = kwargs.get('result_database')
        captured_run_id = kwargs.get('completed_run_id')
        now = datetime.now(UTC)
        return (
            CompletedResult.finish(
                run_id=captured_run_id,
                target=options.domain,
                started_at=now,
                completed_at=now,
                groups={},
            ),
        )

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> tuple[Path, str]:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='example.test',
                sources=[],
                vhost_endpoint='https://192.0.2.8',
                vhost_candidates=['admin.example.test'],
                vhost_request_limit=12,
                vhost_runtime_seconds=9,
                vhost_timeout_seconds=2,
                vhost_concurrency=1,
                vhost_insecure=True,
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)
        return store.database, created['run_id']

    database, run_id = asyncio.run(scenario())

    assert captured is not None
    assert captured.vhost is True
    assert captured.vhost_endpoint == 'https://192.0.2.8:443/'
    assert captured.vhost_candidates == ('admin.example.test',)
    assert captured.vhost_request_limit == 12
    assert captured.vhost_runtime_seconds == 9
    assert captured.vhost_timeout_seconds == 2
    assert captured.vhost_concurrency == 1
    assert captured.vhost_insecure is True
    assert captured_database == database
    assert str(captured_run_id) == run_id


def test_api_scan_child_uses_operator_endpoint_paths(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_wordlists: list[Path] = []

    async def fake_start(options, **_kwargs):
        received_wordlists.append(Path(options.wordlist))
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='api.example.test',
                sources=[],
                api_scan=True,
                api_scan_paths=['/api/v2', '/health'],
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_wordlists[0].read_text(encoding='utf-8') == '/api/v2\n/health\n'


def test_running_cancellation_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'enabled')

    async def slow_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'example.test',
                    'status': 'partial',
                    'results': [{'type': 'email', 'value': 'saved@example.test'}],
                }
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    application = api.create_app(runtime_factory=lambda: runtime_with_process_factory(slow_process))
    headers = {'X-API-Key': 'test-key'}
    with TestClient(application) as client:
        submitted = client.post(
            '/api/v1/runs',
            headers=headers,
            json={'target': 'example.test', 'sources': ['crtsh'], 'deadline_seconds': 60},
        ).json()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            detail = client.get(f'/api/v1/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'running':
                break
            time.sleep(0.02)
        requested = client.post(f'/api/v1/runs/{submitted["run_id"]}/cancel', headers=headers)
        while time.monotonic() < deadline:
            detail = client.get(f'/api/v1/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'cancelled':
                break
            time.sleep(0.02)

    assert requested.json()['status'] == 'cancelling'
    assert detail['status'] == 'cancelled'
    assert detail['completed_at'] is not None
    assert detail['evidence_status'] == 'partial'
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test', 'sources': [], 'actions': []}]


def test_whole_run_deadline_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def slow_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'example.test',
                    'status': 'partial',
                    'results': [{'type': 'email', 'value': 'saved@example.test'}],
                }
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    worker = run_worker.RunWorker(process_factory=slow_process)

    async def scenario():
        store = RunStore()
        await store.create(RunRequest(target='example.test', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        run['request']['deadline_seconds'] = 0
        await worker.execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert 'deadline' in detail['error']
    assert detail['evidence_status'] == 'partial'
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test', 'sources': [], 'actions': []}]


def test_cancelling_execute_claimed_terminates_the_child_process(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario() -> None:
        processes: list[asyncio.subprocess.Process] = []
        process_started = asyncio.Event()

        async def slow_process(_run_id, _database, _artifact_dir):
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                '-c',
                'import time; time.sleep(60)',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            processes.append(process)
            process_started.set()
            return process

        worker = run_worker.RunWorker(process_factory=slow_process)
        store = RunStore(tmp_path / 'runs.sqlite')
        await store.create(RunRequest(target='example.test', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None

        execution = asyncio.create_task(worker.execute_claimed(store, run))
        await asyncio.wait_for(process_started.wait(), timeout=2)
        try:
            execution.cancel()
            with pytest.raises(asyncio.CancelledError):
                await execution
            assert processes[0].returncode is not None
        finally:
            for process in processes:
                if process.returncode is None:
                    process.kill()
                    await process.wait()

    asyncio.run(scenario())


def test_worker_fails_run_without_attaching_child_evidence_for_another_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def mismatched_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'different.example',
                    'status': 'complete',
                    'results': [{'type': 'email', 'value': 'saved@different.example'}],
                }
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'pass',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    worker = run_worker.RunWorker(process_factory=mismatched_process)

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        await store.create(RunRequest(target='expected.example', sources=['crtsh'], dns_resolve=True))
        run = await store.claim_next()
        assert run is not None
        assert run['request']['deadline_seconds'] is None
        await worker.execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert detail['results'] == []
    assert 'does not match run target' in detail['error']


@pytest.mark.parametrize('source_workers', [0, -1, True, 1.5])
def test_run_request_requires_positive_source_workers(source_workers: object) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError):
        RunRequest(target='example.test', sources=['crtsh'], source_workers=source_workers)


def test_source_workers_are_preserved_from_rest_request_to_child(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='example.test', sources=['crtsh'], source_workers=7))
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source_workers == 7
