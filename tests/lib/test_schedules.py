from __future__ import annotations

import asyncio
import stat
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.runtime_helpers import ready_worker


def _payload(*, start_at: str = '2026-08-20T09:00:00-04:00', targets: list[str] | None = None) -> dict[str, object]:
    selected_targets = targets or ['example.test', 'example.org']
    return {
        'name': 'Daily inventory',
        'targets': selected_targets,
        'run': {
            'target': selected_targets[0],
            'sources': ['crtsh'],
            'limit': 100,
        },
        'timing': {
            'frequency': 'daily',
            'start_at': start_at,
            'timezone': 'America/New_York',
            'interval': 1,
            'weekdays': [],
        },
        'enabled': True,
        'overlap_policy': 'skip',
    }


def test_daily_schedule_preserves_local_wall_clock_across_dst() -> None:
    from theHarvester.lib.api.schedule_models import ScheduleTiming

    timing = ScheduleTiming.model_validate(
        {
            'frequency': 'daily',
            'start_at': '2026-10-31T09:00:00-04:00',
            'timezone': 'America/New_York',
            'interval': 1,
        }
    )

    next_run = timing.next_after(datetime(2026, 11, 1, 12, 0, tzinfo=UTC))

    assert next_run == datetime(2026, 11, 1, 14, 0, tzinfo=UTC)


def test_monthly_schedule_uses_the_final_day_of_short_months() -> None:
    from theHarvester.lib.api.schedule_models import ScheduleTiming

    timing = ScheduleTiming.model_validate(
        {
            'frequency': 'monthly',
            'start_at': '2027-01-31T09:00:00-05:00',
            'timezone': 'America/New_York',
            'interval': 1,
        }
    )

    february = timing.next_after(datetime(2027, 1, 31, 14, tzinfo=UTC))
    march = timing.next_after(datetime(2027, 2, 28, 14, tzinfo=UTC))

    assert february == datetime(2027, 2, 28, 14, tzinfo=UTC)
    assert march == datetime(2027, 3, 31, 13, tzinfo=UTC)

    every_two_months = timing.model_copy(update={'interval': 2})
    assert every_two_months.next_after(datetime(2027, 1, 31, 14, tzinfo=UTC)) == datetime(2027, 3, 31, 13, tzinfo=UTC)


def test_schedule_api_persists_bulk_targets_without_enabling_network_work(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        created = client.post('/api/v1/schedules', headers=headers, json=_payload())
        listed = client.get('/api/v1/schedules', headers=headers)

    assert created.status_code == 201
    assert created.json()['targets'] == ['example.test', 'example.org']
    assert created.json()['run']['sources'] == ['crtsh']
    assert listed.status_code == 200
    assert [schedule['schedule_id'] for schedule in listed.json()] == [created.json()['schedule_id']]


def test_schedule_api_exposes_five_upcoming_monthly_occurrences(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    payload = _payload(start_at='2027-01-31T09:00:00-05:00', targets=['example.test'])
    payload['timing']['frequency'] = 'monthly'

    with TestClient(api.app) as client:
        created = client.post('/api/v1/schedules', headers=headers, json=payload)
        schedule_id = created.json()['schedule_id']
        paused = client.post(f'/api/v1/schedules/{schedule_id}/pause', headers=headers)

    assert created.status_code == 201
    assert created.json()['upcoming_occurrences'] == [
        '2027-01-31T14:00:00+00:00',
        '2027-02-28T14:00:00+00:00',
        '2027-03-31T13:00:00+00:00',
        '2027-04-30T13:00:00+00:00',
        '2027-05-31T13:00:00+00:00',
    ]
    assert paused.json()['upcoming_occurrences'] == []


def test_schedule_health_reports_disabled_execution_services(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')

    with TestClient(api.app) as client:
        response = client.get('/api/v1/schedules/health', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 200
    assert response.json() == {
        'scheduler_enabled': False,
        'scheduler_available': False,
        'worker_enabled': False,
        'worker_available': False,
    }


def test_schedule_api_requires_authentication(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')

    with TestClient(api.app) as client:
        response = client.get('/api/v1/schedules')

    assert response.status_code in {401, 403}


def test_run_now_queues_one_normal_run_per_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        schedule_store = ScheduleStore()
        schedule = await schedule_store.create(
            ScheduleCreate.model_validate(_payload(targets=['example.test', 'example.org', 'example.net']))
        )
        dispatcher = ScheduleDispatcher(schedule_store, RunStore(), worker=ready_worker())
        dispatched = await dispatcher.dispatch_now(schedule.schedule_id)
        assert dispatched is not None
        assert len(dispatched.run_ids) == 3
        runs = await RunStore().list_runs(limit=10)
        assert {run['target'] for run in runs} == {'example.test', 'example.org', 'example.net'}
        assert all(run['status'] == 'queued' for run in runs)
        dispatches = await schedule_store.list_dispatches(schedule.schedule_id)
        assert {dispatch.target for dispatch in dispatches} == {'example.test', 'example.org', 'example.net'}
        assert {dispatch.scheduled_for for dispatch in dispatches} == {dispatched.scheduled_for}

    asyncio.run(scenario())


def test_pause_resume_and_delete_schedule(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        created = client.post('/api/v1/schedules', headers=headers, json=_payload()).json()
        schedule_id = created['schedule_id']
        paused = client.post(f'/api/v1/schedules/{schedule_id}/pause', headers=headers)
        resumed = client.post(f'/api/v1/schedules/{schedule_id}/resume', headers=headers)
        deleted = client.delete(f'/api/v1/schedules/{schedule_id}', headers=headers)
        missing = client.get(f'/api/v1/schedules/{schedule_id}', headers=headers)

    assert paused.json()['enabled'] is False
    assert paused.json()['next_run_at'] is None
    assert resumed.json()['enabled'] is True
    assert deleted.status_code == 204
    assert missing.status_code == 404


def test_replacing_a_completed_once_schedule_resets_occurrence_state(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import schedule_store
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setattr(schedule_store, 'utc_now_datetime', lambda: datetime(2029, 1, 2, tzinfo=UTC))
    original_payload = _payload(start_at='2029-01-01T09:00:00+00:00')
    original_payload['timing'] = {
        'frequency': 'once',
        'start_at': '2029-01-01T09:00:00+00:00',
        'timezone': 'UTC',
        'interval': 1,
        'weekdays': [],
    }
    replacement_payload = _payload(start_at='2030-01-01T09:00:00+00:00')
    replacement_payload['timing'] = {
        'frequency': 'once',
        'start_at': '2030-01-01T09:00:00+00:00',
        'timezone': 'UTC',
        'interval': 1,
        'weekdays': [],
    }
    replacement_payload['enabled'] = False

    async def scenario() -> None:
        store = ScheduleStore()
        created = await store.create(ScheduleCreate.model_validate(original_payload))
        run_id = '99999999-9999-4999-8999-999999999999'
        await store.reserve_dispatch(
            created.schedule_id,
            datetime(2029, 1, 1, 9, tzinfo=UTC),
            'example.test',
            run_id,
        )
        await store.set_dispatch_state(run_id, 'completed')
        claimed = await store.claim_due('scheduler-a', now=datetime(2029, 1, 1, 10, tzinfo=UTC))
        assert [schedule.schedule_id for schedule in claimed] == [created.schedule_id]
        assert await store.complete_claim(
            created.schedule_id,
            'scheduler-a',
            scheduled_for=datetime(2029, 1, 1, 9, tzinfo=UTC),
            next_run_at=None,
        )

        replaced = await store.replace(created.schedule_id, ScheduleCreate.model_validate(replacement_payload))
        assert replaced is not None
        assert replaced.last_run_at == '2029-01-01T09:00:00+00:00'
        resumed = await store.set_enabled(created.schedule_id, True)
        assert resumed is not None
        assert resumed.next_run_at == '2030-01-01T09:00:00+00:00'
        assert [dispatch.run_id for dispatch in await store.list_dispatches(created.schedule_id)] == [run_id]

    asyncio.run(scenario())


def test_replacing_a_recurring_schedule_advances_without_replaying_past_occurrences(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import schedule_store
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    now = datetime(2029, 1, 10, 12, tzinfo=UTC)
    monkeypatch.setattr(schedule_store, 'utc_now_datetime', lambda: now)
    payload = _payload(start_at='2029-01-01T09:00:00+00:00', targets=['example.test'])
    payload['timing']['timezone'] = 'UTC'

    async def scenario() -> None:
        store = ScheduleStore()
        created = await store.create(ScheduleCreate.model_validate(payload))
        await store.claim_due('scheduler-a', now=datetime(2029, 1, 1, 10, tzinfo=UTC))
        assert await store.complete_claim(
            created.schedule_id,
            'scheduler-a',
            scheduled_for=datetime(2029, 1, 1, 9, tzinfo=UTC),
            next_run_at=datetime(2029, 1, 2, 9, tzinfo=UTC),
        )
        payload['name'] = 'Renamed inventory'

        replaced = await store.replace(created.schedule_id, ScheduleCreate.model_validate(payload))

        assert replaced is not None
        assert replaced.last_run_at == '2029-01-01T09:00:00+00:00'
        assert replaced.next_run_at == '2029-01-11T09:00:00+00:00'

    asyncio.run(scenario())


def test_replacing_an_unrun_overdue_once_schedule_preserves_its_pending_occurrence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import schedule_store
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setattr(schedule_store, 'utc_now_datetime', lambda: datetime(2029, 1, 2, tzinfo=UTC))
    payload = _payload(start_at='2029-01-01T09:00:00+00:00', targets=['example.test'])
    payload['timing'] = {
        'frequency': 'once',
        'start_at': '2029-01-01T09:00:00+00:00',
        'timezone': 'UTC',
        'interval': 1,
        'weekdays': [],
    }

    async def scenario() -> None:
        store = ScheduleStore()
        created = await store.create(ScheduleCreate.model_validate(payload))
        payload['name'] = 'Renamed pending inventory'

        replaced = await store.replace(created.schedule_id, ScheduleCreate.model_validate(payload))

        assert replaced is not None
        assert replaced.last_run_at is None
        assert replaced.next_run_at == '2029-01-01T09:00:00+00:00'

    asyncio.run(scenario())


def test_run_now_rejects_an_unavailable_worker_without_creating_runs(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        schedule_id = client.post('/api/v1/schedules', headers=headers, json=_payload()).json()['schedule_id']
        response = client.post(f'/api/v1/schedules/{schedule_id}/run-now', headers=headers)

    assert response.status_code == 503
    assert asyncio.run(RunStore().list_runs(limit=10)) == []


def test_recurrence_handles_intervals_dst_and_downtime() -> None:
    from theHarvester.lib.api.schedule_models import ScheduleTiming

    once = ScheduleTiming(
        frequency='once',
        start_at=datetime(2026, 8, 20, 10, tzinfo=UTC),
    )
    assert once.next_after(datetime(2026, 8, 20, 9, tzinfo=UTC)) == datetime(2026, 8, 20, 10, tzinfo=UTC)
    assert once.next_after(datetime(2026, 8, 20, 10, tzinfo=UTC)) is None
    assert once.next_future_after(datetime(2026, 8, 20, 10, tzinfo=UTC)) is None

    hourly = ScheduleTiming(
        frequency='hourly',
        start_at=datetime(2026, 8, 20, 10, tzinfo=UTC),
        interval=3,
    )
    assert hourly.next_after(datetime(2026, 8, 20, 16, tzinfo=UTC)) == datetime(2026, 8, 20, 19, tzinfo=UTC)
    assert hourly.next_future_after(
        datetime(2026, 8, 20, 10, tzinfo=UTC),
        datetime(2026, 8, 21, 1, tzinfo=UTC),
    ) == datetime(2026, 8, 21, 4, tzinfo=UTC)

    every_seven_days = ScheduleTiming(
        frequency='daily',
        start_at=datetime.fromisoformat('2026-08-20T09:00:00-04:00'),
        timezone='America/New_York',
        interval=7,
    )
    assert every_seven_days.next_after(datetime(2026, 8, 20, 13, tzinfo=UTC)) == datetime(2026, 8, 27, 13, tzinfo=UTC)
    assert every_seven_days.upcoming_occurrences(
        datetime(2026, 8, 20, 13, tzinfo=UTC),
        limit=3,
        now=datetime(2026, 8, 30, 13, tzinfo=UTC),
    ) == [
        datetime(2026, 8, 20, 13, tzinfo=UTC),
        datetime(2026, 9, 3, 13, tzinfo=UTC),
        datetime(2026, 9, 10, 13, tzinfo=UTC),
    ]

    spring = ScheduleTiming(
        frequency='daily',
        start_at=datetime.fromisoformat('2026-03-01T02:30:00-05:00'),
        timezone='America/New_York',
    )
    assert spring.next_after(datetime(2026, 3, 8, 6, 59, tzinfo=UTC)) == datetime(2026, 3, 8, 7, 30, tzinfo=UTC)

    fall = ScheduleTiming(
        frequency='daily',
        start_at=datetime.fromisoformat('2026-10-31T01:30:00-04:00'),
        timezone='America/New_York',
    )
    assert fall.next_after(datetime(2026, 11, 1, 5, 0, tzinfo=UTC)) == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)

    weekly = ScheduleTiming(
        frequency='weekly',
        start_at=datetime.fromisoformat('2026-08-17T09:00:00-04:00'),
        timezone='America/New_York',
        interval=2,
        weekdays=[1, 5],
    )
    assert weekly.next_after(datetime(2026, 8, 21, 13, tzinfo=UTC)) == datetime(2026, 8, 31, 13, tzinfo=UTC)

    weekly_after_start = ScheduleTiming(
        frequency='weekly',
        start_at=datetime.fromisoformat('2026-08-20T09:00:00-04:00'),
        timezone='America/New_York',
        weekdays=[3],
    )
    assert weekly_after_start.first_due_at() == datetime(2026, 8, 26, 13, tzinfo=UTC)


def test_schedule_validation_rejects_blank_names_duplicates_and_invalid_target_templates() -> None:
    from theHarvester.lib.api.schedule_models import ScheduleCreate

    with pytest.raises(ValidationError, match='name must not be blank'):
        ScheduleCreate.model_validate({**_payload(), 'name': '   '})
    with pytest.raises(ValidationError, match='targets must not contain duplicates'):
        ScheduleCreate.model_validate(_payload(targets=['Example.Test.', 'example.test']))

    payload = _payload(targets=['example.test', '192.0.2.1'])
    payload['run'] = {'target': 'example.test', 'sources': ['crtsh'], 'vhost': True}
    with pytest.raises(ValidationError, match='Virtual-host discovery requires a hostname target scope'):
        ScheduleCreate.model_validate(payload)


def test_schedule_database_rejects_symlinks_and_is_private(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.schedule_store import ScheduleStore, ScheduleStoreError

    real_database = tmp_path / 'real.sqlite'
    real_database.touch()
    linked_database = tmp_path / 'linked.sqlite'
    linked_database.symlink_to(real_database)

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(linked_database))
    with pytest.raises(ScheduleStoreError, match='Refusing symlinked schedule database'):
        asyncio.run(ScheduleStore().initialize())

    private_database = tmp_path / 'private.sqlite'
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(private_database))
    asyncio.run(ScheduleStore().initialize())
    assert stat.S_IMODE(private_database.stat().st_mode) == 0o600


def test_schedule_database_rechecks_symlink_before_each_connection(tmp_path) -> None:
    from theHarvester.lib.api.schedule_store import ScheduleStore, ScheduleStoreError

    async def scenario() -> None:
        store = ScheduleStore(tmp_path / 'runs.sqlite')
        database = store.database
        original_database = tmp_path / 'original.sqlite'
        await store.initialize()
        database.rename(original_database)
        database.symlink_to(original_database)

        with pytest.raises(ScheduleStoreError, match='Refusing symlinked schedule database'):
            await store.list_schedules()

    asyncio.run(scenario())


def test_schedule_store_reconnects_after_shared_engines_are_disposed(tmp_path) -> None:
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore, dispose_schedule_databases

    async def scenario() -> None:
        store = ScheduleStore(tmp_path / 'runs.sqlite')
        created = await store.create(ScheduleCreate.model_validate(_payload()))

        await dispose_schedule_databases()

        reloaded = await store.get(created.schedule_id)
        assert reloaded is not None
        assert reloaded.targets == created.targets

    asyncio.run(scenario())


def test_schedule_store_reserves_the_maximum_target_batch(tmp_path) -> None:
    from theHarvester.lib.api.schedule_models import MAX_SCHEDULE_TARGETS, ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore

    async def scenario() -> None:
        store = ScheduleStore(tmp_path / 'runs.sqlite')
        targets = [f'asset-{index}.example.test' for index in range(MAX_SCHEDULE_TARGETS)]
        schedule = await store.create(ScheduleCreate.model_validate(_payload(targets=targets)))
        scheduled_for = datetime(2026, 8, 20, 13, tzinfo=UTC)

        dispatches = await store.reserve_dispatches(
            schedule.schedule_id,
            scheduled_for,
            {target: str(UUID(int=index + 1)) for index, target in enumerate(targets)},
        )

        assert len(dispatches) == MAX_SCHEDULE_TARGETS
        assert [dispatch.target for dispatch in dispatches] == targets

    asyncio.run(scenario())


def test_dispatch_recovery_reuses_reservations_and_run_ids(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import schedule_service
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        schedule_store = ScheduleStore()
        run_store = RunStore()
        schedule = await schedule_store.create(ScheduleCreate.model_validate(_payload()))
        scheduled_for = datetime(2026, 8, 20, 13, tzinfo=UTC)
        monkeypatch.setattr(schedule_service, 'utc_now_datetime', lambda: scheduled_for)
        first_run_id = '11111111-1111-4111-8111-111111111111'
        second_run_id = '22222222-2222-4222-8222-222222222222'
        await schedule_store.reserve_dispatch(schedule.schedule_id, scheduled_for, 'example.test', first_run_id)
        await schedule_store.reserve_dispatch(schedule.schedule_id, scheduled_for, 'example.org', second_run_id)
        await run_store.create(RunRequest(target='example.org', sources=['crtsh']), run_id=second_run_id)

        dispatcher = ScheduleDispatcher(schedule_store, run_store, worker=ready_worker())
        recovered = await dispatcher.dispatch_now(schedule.schedule_id)
        duplicate = await dispatcher.dispatch_now(schedule.schedule_id)

        assert recovered is not None
        assert duplicate is not None
        assert recovered.run_ids == [first_run_id, second_run_id]
        assert duplicate.run_ids == []
        assert duplicate.skipped_targets == ['example.test', 'example.org']
        assert {run['run_id'] for run in await run_store.list_runs(limit=10)} == {first_run_id, second_run_id}

    asyncio.run(scenario())


@pytest.mark.parametrize('overlap_policy', ['skip', 'queue'])
def test_overlap_policy_recovers_current_occurrence_reservations(tmp_path, monkeypatch, overlap_policy: str) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        run_store = RunStore()
        scheduled_for = datetime(2026, 8, 20, 9, tzinfo=UTC)
        payload = _payload(start_at=scheduled_for.isoformat())
        payload['overlap_policy'] = overlap_policy
        schedule = await store.create(ScheduleCreate.model_validate(payload))
        first_run_id = '55555555-5555-4555-8555-555555555555'
        second_run_id = '66666666-6666-4666-8666-666666666666'
        await store.reserve_dispatch(schedule.schedule_id, scheduled_for, 'example.test', first_run_id)
        await store.reserve_dispatch(schedule.schedule_id, scheduled_for, 'example.org', second_run_id)
        await run_store.create(RunRequest(target='example.org', sources=['crtsh']), run_id=second_run_id)

        claimed = await store.claim_due('recovery-owner', now=scheduled_for, limit=1)
        await ScheduleDispatcher(store, run_store, worker=ready_worker()).dispatch_claimed(claimed[0], 'recovery-owner')

        dispatches = await store.list_dispatches(schedule.schedule_id)
        updated = await store.get(schedule.schedule_id)
        assert {dispatch.run_id for dispatch in dispatches} == {first_run_id, second_run_id}
        assert {dispatch.state for dispatch in dispatches} == {'queued'}
        assert {run['run_id'] for run in await run_store.list_runs(limit=10)} == {first_run_id, second_run_id}
        assert updated is not None
        assert updated.last_run_at == scheduled_for.isoformat()
        assert updated.last_error is None

    asyncio.run(scenario())


def test_recovered_queued_occurrence_completes_without_a_false_error(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        run_store = RunStore()
        scheduled_for = datetime(2026, 8, 20, 9, tzinfo=UTC)
        schedule = await store.create(
            ScheduleCreate.model_validate(_payload(start_at=scheduled_for.isoformat(), targets=['example.test']))
        )
        run_id = '77777777-7777-4777-8777-777777777777'
        await store.reserve_dispatch(schedule.schedule_id, scheduled_for, 'example.test', run_id)
        await run_store.create(RunRequest(target='example.test', sources=['crtsh']), run_id=run_id)
        await store.set_dispatch_state(run_id, 'queued')

        claimed = await store.claim_due('recovery-owner', now=scheduled_for, limit=1)
        await ScheduleDispatcher(store, run_store, worker=ready_worker()).dispatch_claimed(claimed[0], 'recovery-owner')

        updated = await store.get(schedule.schedule_id)
        assert updated is not None
        assert updated.last_run_at == scheduled_for.isoformat()
        assert updated.last_error is None
        assert [run['run_id'] for run in await run_store.list_runs(limit=10)] == [run_id]

    asyncio.run(scenario())


@pytest.mark.parametrize('transition', ['pause-resume', 'replace'])
@pytest.mark.parametrize('overlap_policy', ['skip', 'queue'])
def test_newer_occurrence_terminalizes_a_stale_runless_reservation(
    tmp_path,
    monkeypatch,
    transition: str,
    overlap_policy: str,
) -> None:
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate, parse_utc
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        first = datetime(2020, 1, 1, tzinfo=UTC)
        stale = datetime(2020, 1, 1, 1, tzinfo=UTC)
        payload = _payload(start_at=first.isoformat(), targets=['example.test'])
        payload['timing']['frequency'] = 'hourly'
        payload['overlap_policy'] = overlap_policy
        schedule = await store.create(ScheduleCreate.model_validate(payload))
        assert (await store.claim_due('first-owner', now=first))[0].schedule_id == schedule.schedule_id
        assert await store.complete_claim(
            schedule.schedule_id,
            'first-owner',
            scheduled_for=first,
            next_run_at=stale,
        )
        stale_run_id = '88888888-8888-4888-8888-888888888888'
        await store.reserve_dispatch(schedule.schedule_id, stale, 'example.test', stale_run_id)

        if transition == 'pause-resume':
            assert await store.set_enabled(schedule.schedule_id, False) is not None
            changed = await store.set_enabled(schedule.schedule_id, True)
        else:
            replacement = _payload(start_at='2030-01-01T09:00:00+00:00', targets=['example.test'])
            replacement['timing']['frequency'] = 'hourly'
            replacement['overlap_policy'] = overlap_policy
            changed = await store.replace(schedule.schedule_id, ScheduleCreate.model_validate(replacement))
        assert changed is not None
        assert changed.next_run_at is not None
        current = parse_utc(changed.next_run_at)
        claimed = await store.claim_due('current-owner', now=current)
        await ScheduleDispatcher(store, RunStore(), worker=ready_worker()).dispatch_claimed(claimed[0], 'current-owner')

        dispatches = await store.list_dispatches(schedule.schedule_id)
        stale_dispatch = next(dispatch for dispatch in dispatches if dispatch.run_id == stale_run_id)
        assert stale_dispatch.state == 'failed'
        assert stale_dispatch.error == 'Reserved occurrence was superseded before run creation'
        current_dispatches = [dispatch for dispatch in dispatches if dispatch.scheduled_for == changed.next_run_at]
        assert len(current_dispatches) == 1
        assert current_dispatches[0].state == 'queued'
        assert [run['run_id'] for run in await RunStore().list_runs(limit=10)] == [current_dispatches[0].run_id]

    asyncio.run(scenario())


def test_large_reservation_reconciliation_renews_the_schedule_claim(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate, parse_utc
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    renewals = 0
    renew_claim = ScheduleStore.renew_claim

    async def track_renewal(self, schedule_id: str, owner_id: str, *, lease_seconds: int = 60) -> bool:
        nonlocal renewals
        renewals += 1
        return await renew_claim(self, schedule_id, owner_id, lease_seconds=lease_seconds)

    monkeypatch.setattr(ScheduleStore, 'renew_claim', track_renewal)

    async def scenario() -> None:
        store = ScheduleStore()
        first = datetime(2020, 1, 1, tzinfo=UTC)
        stale = datetime(2020, 1, 1, 1, tzinfo=UTC)
        payload = _payload(start_at=first.isoformat(), targets=['example.test'])
        payload['timing']['frequency'] = 'hourly'
        payload['overlap_policy'] = 'queue'
        schedule = await store.create(ScheduleCreate.model_validate(payload))
        assert (await store.claim_due('first-owner', now=first))[0].schedule_id == schedule.schedule_id
        assert await store.complete_claim(
            schedule.schedule_id,
            'first-owner',
            scheduled_for=first,
            next_run_at=stale,
        )
        for index in range(100):
            await store.reserve_dispatch(
                schedule.schedule_id,
                stale,
                f'example-{index}.test',
                f'00000000-0000-4000-8000-{index:012d}',
            )

        assert await store.set_enabled(schedule.schedule_id, False) is not None
        changed = await store.set_enabled(schedule.schedule_id, True)
        assert changed is not None
        assert changed.next_run_at is not None
        current = parse_utc(changed.next_run_at)
        claimed = await store.claim_due('current-owner', now=current)
        await ScheduleDispatcher(store, RunStore(), worker=ready_worker()).dispatch_claimed(claimed[0], 'current-owner')

        dispatches = await store.list_dispatches(schedule.schedule_id)
        assert renewals == 2
        assert sum(dispatch.state == 'failed' for dispatch in dispatches) == 100
        assert sum(dispatch.state == 'queued' for dispatch in dispatches) == 1

    asyncio.run(scenario())


def test_deferred_claim_keeps_occurrence_identity(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.schedule_models import ScheduleCreate, parse_utc
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        due = datetime(2026, 8, 20, 9, tzinfo=UTC)
        schedule = await store.create(ScheduleCreate.model_validate(_payload(start_at=due.isoformat())))
        claimed = await store.claim_due('first-owner', now=due, limit=1)
        assert claimed[0].next_run_at == due.isoformat()

        await store.defer_claim(schedule.schedule_id, 'first-owner', seconds=60, error='retry')
        deferred = await store.get(schedule.schedule_id)
        assert deferred is not None
        assert deferred.next_run_at == due.isoformat()
        utc_now = parse_utc(deferred.updated_at)
        assert await store.claim_due('too-early', now=utc_now, limit=1) == []
        retried = await store.claim_due('second-owner', now=max(due, utc_now) + timedelta(seconds=61), limit=1)
        assert retried[0].next_run_at == due.isoformat()

    asyncio.run(scenario())


def test_dispatch_mirrors_cancelling_run_state(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        schedule_store = ScheduleStore()
        run_store = RunStore()
        schedule = await schedule_store.create(ScheduleCreate.model_validate(_payload()))
        run = await run_store.create(RunRequest(target='example.test', sources=['crtsh']))
        await schedule_store.reserve_dispatch(
            schedule.schedule_id,
            datetime(2026, 8, 20, 13, tzinfo=UTC),
            'example.test',
            run['run_id'],
        )
        await schedule_store.set_dispatch_state(run['run_id'], 'queued')
        assert await run_store.claim_next() is not None
        cancelled = await run_store.cancel(run['run_id'])
        assert cancelled is not None
        assert cancelled['status'] == 'cancelling'

        await ScheduleDispatcher(schedule_store, run_store, worker=ready_worker()).refresh(schedule.schedule_id)

        dispatch = (await schedule_store.list_dispatches(schedule.schedule_id))[0]
        assert dispatch.state == 'cancelling'

    asyncio.run(scenario())


def test_two_scheduler_instances_cannot_claim_the_same_occurrence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        await store.create(ScheduleCreate.model_validate(_payload(start_at='2026-08-20T09:00:00+00:00')))
        claims = await asyncio.gather(
            ScheduleStore().claim_due('first', now=datetime(2026, 8, 20, 10, tzinfo=UTC), limit=1),
            ScheduleStore().claim_due('second', now=datetime(2026, 8, 20, 10, tzinfo=UTC), limit=1),
        )
        assert sorted(len(claimed) for claimed in claims) == [0, 1]

    asyncio.run(scenario())


def test_claimed_occurrence_fails_closed_after_claim_loss(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def scenario() -> None:
        store = ScheduleStore()
        due = datetime(2026, 8, 20, 9, tzinfo=UTC)
        schedule = await store.create(ScheduleCreate.model_validate(_payload(start_at=due.isoformat())))
        claimed = (await store.claim_due('first-owner', now=due, limit=1))[0]
        await store.release_claims('first-owner')

        with pytest.raises(RuntimeError, match='lost its occurrence claim'):
            await ScheduleDispatcher(store, RunStore(), worker=ready_worker()).dispatch_claimed(claimed, 'first-owner')

        assert await store.list_dispatches(schedule.schedule_id) == []
        assert await RunStore().list_runs(limit=10) == []

    asyncio.run(scenario())


def test_claim_loss_during_enqueue_leaves_every_target_auditable(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    renew_claim = ScheduleStore.renew_claim
    renewals = 0

    async def lose_second_renewal(self, schedule_id: str, owner_id: str, *, lease_seconds: int = 60) -> bool:
        nonlocal renewals
        renewals += 1
        if renewals == 1:
            return await renew_claim(self, schedule_id, owner_id, lease_seconds=lease_seconds)
        await self.release_claims(owner_id)
        return False

    monkeypatch.setattr(ScheduleStore, 'renew_claim', lose_second_renewal)

    async def scenario() -> None:
        store = ScheduleStore()
        due = datetime(2026, 8, 20, 9, tzinfo=UTC)
        targets = [f'asset-{index}.example.test' for index in range(101)]
        schedule = await store.create(ScheduleCreate.model_validate(_payload(start_at=due.isoformat(), targets=targets)))
        claimed = (await store.claim_due('first-owner', now=due, limit=1))[0]

        with pytest.raises(RuntimeError, match='lost its occurrence claim'):
            await ScheduleDispatcher(store, RunStore(), worker=ready_worker()).dispatch_claimed(claimed, 'first-owner')

        dispatches = await store.list_dispatches(schedule.schedule_id)
        assert len(dispatches) == len(targets)
        assert sum(dispatch.state == 'queued' for dispatch in dispatches) == 100
        assert sum(dispatch.state == 'reserved' for dispatch in dispatches) == 1

    asyncio.run(scenario())


def test_due_schedules_skip_or_queue_while_a_prior_batch_is_active(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.schedule_models import ScheduleCreate
    from theHarvester.lib.api.schedule_service import ScheduleDispatcher
    from theHarvester.lib.api.schedule_store import ScheduleStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))

    async def run_policy(policy: str, owner: str, prior_run_id: str) -> tuple[int, str | None]:
        store = ScheduleStore()
        payload = {**_payload(start_at='2026-08-20T09:00:00+00:00'), 'name': policy, 'overlap_policy': policy}
        schedule = await store.create(ScheduleCreate.model_validate(payload))
        prior = datetime(2026, 8, 19, 9, tzinfo=UTC)
        await store.reserve_dispatch(schedule.schedule_id, prior, 'example.test', prior_run_id)
        await RunStore().create(RunRequest(target='example.test', sources=['crtsh']), run_id=prior_run_id)
        await store.set_dispatch_state(prior_run_id, 'queued')
        claimed = await store.claim_due(owner, now=datetime(2026, 8, 20, 10, tzinfo=UTC), limit=1)
        assert len(claimed) == 1
        await ScheduleDispatcher(store, RunStore(), worker=ready_worker()).dispatch_claimed(claimed[0], owner)
        updated = await store.get(schedule.schedule_id)
        assert updated is not None
        return len(await store.list_dispatches(schedule.schedule_id)), updated.last_error

    async def scenario() -> None:
        skipped_count, skipped_error = await run_policy(
            'skip',
            'skip-owner',
            '33333333-3333-4333-8333-333333333333',
        )
        queued_count, queued_error = await run_policy(
            'queue',
            'queue-owner',
            '44444444-4444-4444-8444-444444444444',
        )
        assert skipped_count == 1
        assert skipped_error == 'Occurrence skipped because a prior scheduled batch is still active'
        assert queued_count == 3
        assert queued_error is None

    asyncio.run(scenario())


def test_disabled_scheduler_does_not_start(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.schedule_service import SchedulerService

    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    scheduler = SchedulerService(ready_worker())

    async def scenario() -> None:
        await scheduler.start()
        assert scheduler.available is False
        await scheduler.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ('method', 'path'),
    [
        ('GET', '/api/v1/schedules'),
        ('GET', '/api/v1/schedules/health'),
        ('POST', '/api/v1/schedules'),
        ('GET', '/api/v1/schedules/missing'),
        ('PUT', '/api/v1/schedules/missing'),
        ('DELETE', '/api/v1/schedules/missing'),
        ('POST', '/api/v1/schedules/missing/pause'),
        ('POST', '/api/v1/schedules/missing/resume'),
        ('POST', '/api/v1/schedules/missing/run-now'),
        ('GET', '/api/v1/schedules/missing/dispatches'),
    ],
)
def test_every_schedule_route_requires_authentication(method, path, tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')

    with TestClient(api.app) as client:
        response = client.request(method, path, json=_payload() if method in {'POST', 'PUT'} else None)

    assert response.status_code in {401, 403}
