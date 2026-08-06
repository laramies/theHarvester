from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from theHarvester.lib.api import api
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.stash import StashManager


def completed_result(run_id: str, completed_at: datetime) -> CompletedResult:
    return CompletedResult.finish(
        run_id=UUID(run_id),
        target='example.com',
        started_at=completed_at - timedelta(minutes=1),
        completed_at=completed_at,
        groups={'hostname': ['www.example.com']},
    )


@pytest.mark.asyncio
async def test_authenticated_operator_lists_recent_completed_runs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('theHarvester.lib.stash.db_path', str(tmp_path))
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
    manager = StashManager()
    await manager.do_init()
    older = completed_result('11111111-1111-4111-8111-111111111111', datetime(2026, 8, 6, 12, 0, tzinfo=UTC))
    newer = completed_result('22222222-2222-4222-8222-222222222222', datetime(2026, 8, 6, 13, 0, tzinfo=UTC))
    offset_older = completed_result(
        '55555555-5555-4555-8555-555555555555', datetime.fromisoformat('2026-08-06T14:30:00+05:00')
    )
    await manager.store_completed_result(older)
    await manager.store_completed_result(newer)
    await manager.store_completed_result(offset_older)

    response = TestClient(api.app).get('/runs?limit=1', headers={'X-API-Key': 'test-secret'})

    assert response.status_code == 200
    assert response.json() == [
        {
            'run_id': str(newer.run_id),
            'target': 'example.com',
            'started_at': '2026-08-06T12:59:00Z',
            'completed_at': '2026-08-06T13:00:00Z',
            'result_count': 1,
        }
    ]


@pytest.mark.asyncio
async def test_authenticated_operator_gets_one_completed_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('theHarvester.lib.stash.db_path', str(tmp_path))
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
    manager = StashManager()
    await manager.do_init()
    result = CompletedResult.finish(
        run_id=UUID('33333333-3333-4333-8333-333333333333'),
        target='example.com',
        started_at=datetime(2026, 8, 6, 14, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 6, 14, 1, tzinfo=UTC),
        groups={'email': ['security@example.com'], 'hostname': ['www.example.com']},
    )
    await manager.store_completed_result(result)
    client = TestClient(api.app)

    response = client.get(f'/runs/{result.run_id}', headers={'X-API-Key': 'test-secret'})
    missing = client.get('/runs/44444444-4444-4444-8444-444444444444', headers={'X-API-Key': 'test-secret'})

    assert response.status_code == 200
    assert response.json() == {
        'run_id': str(result.run_id),
        'target': 'example.com',
        'started_at': '2026-08-06T14:00:00Z',
        'completed_at': '2026-08-06T14:01:00Z',
        'result_count': 2,
        'results': [
            {'type': 'email', 'value': 'security@example.com'},
            {'type': 'hostname', 'value': 'www.example.com'},
        ],
    }
    assert missing.status_code == 404
    assert missing.json() == {'detail': 'Completed run not found'}


def test_completed_run_routes_fail_closed_without_operator_key(monkeypatch) -> None:
    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    client = TestClient(api.app)

    list_response = client.get('/runs')
    detail_response = client.get('/runs/33333333-3333-4333-8333-333333333333')

    assert list_response.status_code == 503
    assert detail_response.status_code == 503
