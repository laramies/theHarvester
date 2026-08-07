from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime

from fastapi.testclient import TestClient


def test_orphan_recovery_reattaches_partial_checkpoint_and_leaves_queued_work(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_evidence
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
        artifact_dir = run_evidence._artifact_dir(cancelling['run_id'])
        run_evidence._ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        checkpoint = CompletedResult.finish(
            target='first.example',
            started_at=now,
            completed_at=now,
            groups={'email': ['saved@first.example']},
        )
        run_evidence._write_child_evidence(artifact_dir, checkpoint, partial=True)
        running = await store.claim_next()
        assert running is not None
        await store.recover_orphans()
        return await store.get(cancelling['run_id']), await store.get(running['run_id']), await store.list_runs()

    cancelling, running, history = asyncio.run(scenario())

    assert cancelling is not None
    assert cancelling['status'] == 'failed'
    assert cancelling['evidence_status'] == 'partial'
    assert cancelling['results'] == [{'type': 'email', 'value': 'saved@first.example'}]
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
            json={'target': '192.0.2.8', 'sources': ['certspotter'], 'api_scan': True},
        )

    assert response.status_code == 201
    assert response.json()['target'] == '192.0.2.8'
    assert response.json()['request']['api_scan'] is True


def test_running_cancellation_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'enabled')

    async def slow_process(_run_id, artifact_dir):
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
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test'}]


def test_whole_run_deadline_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def slow_process(_run_id, artifact_dir):
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
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test'}]
