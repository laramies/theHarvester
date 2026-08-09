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

from fastapi.testclient import TestClient


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


def test_api_lifespan_disposes_shared_sqlite_engines(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    disposed = False

    async def no_op() -> None:
        return None

    async def dispose() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(api, 'dispose_sqlite_databases', dispose)

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
    assert schema_version == 4
    assert 'import aiosqlite' not in inspect.getsource(run_store_module)


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

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

        async def take_screenshot(self, url: str) -> str:
            captured_url = url if url.startswith('https://') else f'https://{url}'
            self.screenshot_path(captured_url).write_bytes(b'png')
            return captured_url

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    database = tmp_path / 'state' / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(main_module, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(main_module, 'Pool', FakePool)

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
    assert run['results'] == [{'type': 'subdomain', 'value': 'api.example.test', 'sources': [], 'actions': []}]
    assert [screenshot['name'] for screenshot in run['screenshots']] == ['api.example.test.png']
    assert (artifact_dir / 'screenshots' / 'api.example.test.png').read_bytes() == b'png'


def test_sqlite_import_preserves_run_ids_and_is_idempotent(tmp_path) -> None:
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

    async def scenario():
        source = ResultStore(source_database)
        await source.initialize()
        await source.save_run(first)
        await source.save_run(second)
        await dispose_sqlite_databases()
        destination = RunStore(destination_database)
        imported = await destination.import_database(source_database, 'source.sqlite')
        repeated = await destination.import_database(source_database, 'source.sqlite')
        history = await destination.list_runs()
        return imported, repeated, history

    imported, repeated, history = asyncio.run(scenario())

    expected_ids = sorted((str(first.run_id), str(second.run_id)))
    assert imported == {'filename': 'source.sqlite', 'imported_run_ids': expected_ids, 'skipped_run_ids': []}
    assert repeated == {'filename': 'source.sqlite', 'imported_run_ids': [], 'skipped_run_ids': expected_ids}
    assert sorted(run['run_id'] for run in history) == expected_ids


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
        await store.recover_orphans()
        return await store.get(cancelling['run_id']), await store.get(running['run_id']), await store.list_runs()

    cancelling, running, history = asyncio.run(scenario())

    assert cancelling is not None
    assert cancelling['status'] == 'failed'
    assert cancelling['evidence_status'] == 'partial'
    assert cancelling['results'] == [{'type': 'email', 'value': 'saved@first.example', 'sources': [], 'actions': []}]
    assert running is not None
    assert running['status'] == 'failed'
    assert {run['target']: run['status'] for run in history}['third.example'] == 'queued'


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
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('StoppedTask', (), {'done': lambda self: True})())

    with TestClient(api.app) as client:
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
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': '192.0.2.8', 'sources': ['criminalip']},
        )

    assert response.status_code == 201
    assert response.json()['target'] == '192.0.2.8'
    assert response.json()['activities'] == ['P2']


def test_authenticated_operator_can_queue_screenshot_only_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'api.example.com', 'sources': [], 'screenshot': True},
        )

    assert response.status_code == 201
    assert response.json()['target'] == 'api.example.com'
    assert response.json()['sources'] == []
    assert response.json()['activities'] == ['P2']


def test_dns_brute_run_accepts_operator_resolver_list(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
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


def test_running_cancellation_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

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

    monkeypatch.setattr(run_worker, '_process_factory', slow_process)
    headers = {'X-API-Key': 'test-key'}
    with TestClient(api.app) as client:
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
    monkeypatch.setattr(run_worker, '_worker_stop', None)

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

    monkeypatch.setattr(run_worker, '_process_factory', slow_process)

    async def scenario():
        store = RunStore()
        await store.create(RunRequest(target='example.test', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        run['request']['deadline_seconds'] = 0
        await run_worker._execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert 'deadline' in detail['error']
    assert detail['evidence_status'] == 'partial'
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test', 'sources': [], 'actions': []}]
