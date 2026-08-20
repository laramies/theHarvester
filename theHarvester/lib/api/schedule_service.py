from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from . import run_worker
from .run_models import RunRequest
from .run_store import RunStore
from .schedule_models import DispatchState, ScheduleDispatchResponse, ScheduleResponse, parse_utc, utc_iso, utc_now_datetime
from .schedule_store import ScheduleStore

if TYPE_CHECKING:
    from datetime import datetime

_scheduler_task: asyncio.Task[None] | None = None
_scheduler_stop: asyncio.Event | None = None
_scheduler_wakeup: asyncio.Event | None = None
_scheduler_owner: str | None = None


def scheduler_enabled() -> bool:
    return os.getenv('THEHARVESTER_SCHEDULER', 'enabled').casefold() != 'disabled'


def scheduler_available() -> bool:
    return _scheduler_task is not None and not _scheduler_task.done()


def wake_scheduler() -> None:
    if _scheduler_wakeup is not None:
        _scheduler_wakeup.set()


class ScheduleDispatcher:
    """Reserve one scheduled occurrence and submit its ordinary run records."""

    def __init__(self, schedule_store: ScheduleStore | None = None, run_store: RunStore | None = None) -> None:
        self.schedule_store = schedule_store or ScheduleStore()
        self.run_store = run_store or RunStore()

    async def refresh(self, schedule_id: str) -> None:
        await self._reconcile_pending(schedule_id)

    async def dispatch_now(self, schedule_id: str) -> ScheduleDispatchResponse | None:
        schedule = await self.schedule_store.get(schedule_id)
        if schedule is None:
            return None
        if not run_worker.worker_enabled() or not run_worker.worker_available():
            raise RuntimeError('theHarvester execution worker is unavailable')
        return await self._enqueue_targets(schedule, scheduled_for=utc_now_datetime())

    async def dispatch_claimed(self, schedule: ScheduleResponse, owner_id: str) -> None:
        if not await self.schedule_store.renew_claim(schedule.schedule_id, owner_id):
            raise RuntimeError('Scheduler lost its occurrence claim before dispatching scheduled runs')
        if schedule.next_run_at is None:
            await self.schedule_store.complete_claim(
                schedule.schedule_id,
                owner_id,
                scheduled_for=utc_now_datetime(),
                next_run_at=None,
                error='Claimed schedule did not have a next run time',
            )
            return
        scheduled_for = parse_utc(schedule.next_run_at)

        if not run_worker.worker_enabled() or not run_worker.worker_available():
            await self.schedule_store.defer_claim(
                schedule.schedule_id,
                owner_id,
                seconds=60,
                error='Execution worker is unavailable; occurrence deferred',
            )
            return

        active = await self._reconcile_pending(
            schedule.schedule_id,
            current_occurrence=scheduled_for,
            reserved_only=schedule.overlap_policy == 'queue',
            claim_owner=owner_id,
        )
        if schedule.overlap_policy == 'skip' and active:
            next_run = schedule.timing.next_future_after(scheduled_for)
            await self.schedule_store.complete_claim(
                schedule.schedule_id,
                owner_id,
                scheduled_for=scheduled_for,
                next_run_at=next_run,
                error='Occurrence skipped because a prior scheduled batch is still active',
            )
            return

        dispatch = await self._enqueue_targets(schedule, scheduled_for=scheduled_for, claim_owner=owner_id)
        next_run = schedule.timing.next_future_after(scheduled_for)
        errors = list(dispatch.errors)
        if not dispatch.run_ids and dispatch.skipped_targets:
            errors.append('Every target was already reserved for this occurrence')
        await self.schedule_store.complete_claim(
            schedule.schedule_id,
            owner_id,
            scheduled_for=scheduled_for,
            next_run_at=next_run,
            error='; '.join(errors) if errors else None,
        )

    async def _reconcile_pending(
        self,
        schedule_id: str,
        *,
        current_occurrence: datetime | None = None,
        reserved_only: bool = False,
        claim_owner: str | None = None,
    ) -> bool:
        active = False
        dispatches = await self.schedule_store.pending_dispatches(schedule_id, reserved_only=reserved_only)
        for index, dispatch in enumerate(dispatches, start=1):
            if index % 100 == 0:
                if claim_owner is not None and not await self.schedule_store.renew_claim(schedule_id, claim_owner):
                    raise RuntimeError('Scheduler lost its occurrence claim while reconciling scheduled runs')
                await asyncio.sleep(0)
            run = await self.run_store.get(dispatch.run_id)
            if run is None:
                if dispatch.state == 'reserved':
                    if current_occurrence is None:
                        active = True
                    elif parse_utc(dispatch.scheduled_for) != current_occurrence:
                        await self.schedule_store.set_dispatch_state(
                            dispatch.run_id,
                            'failed',
                            'Reserved occurrence was superseded before run creation',
                        )
                    continue
                await self.schedule_store.set_dispatch_state(
                    dispatch.run_id,
                    'failed',
                    'Scheduled run record is missing',
                )
                continue
            status = str(run['status'])
            if status in {'queued', 'running', 'cancelling'}:
                if current_occurrence is None or parse_utc(dispatch.scheduled_for) != current_occurrence:
                    active = True
                state: DispatchState = 'queued' if status == 'queued' else 'running' if status == 'running' else 'cancelling'
                if dispatch.state != state:
                    await self.schedule_store.set_dispatch_state(dispatch.run_id, state)
            elif status == 'completed':
                await self.schedule_store.set_dispatch_state(dispatch.run_id, 'completed')
            elif status == 'cancelled':
                await self.schedule_store.set_dispatch_state(dispatch.run_id, 'cancelled', run.get('error'))
            else:
                await self.schedule_store.set_dispatch_state(dispatch.run_id, 'failed', run.get('error'))
        return active

    async def _enqueue_targets(
        self,
        schedule: ScheduleResponse,
        *,
        scheduled_for: datetime,
        claim_owner: str | None = None,
    ) -> ScheduleDispatchResponse:
        run_ids: list[str] = []
        skipped_targets: list[str] = []
        errors: list[str] = []
        template: dict[str, Any] = schedule.run.model_dump()
        dispatches = await self.schedule_store.reserve_dispatches(
            schedule.schedule_id,
            scheduled_for,
            {target: str(uuid4()) for target in schedule.targets},
        )

        for index, dispatch in enumerate(dispatches, start=1):
            target = dispatch.target
            run_request = RunRequest.model_validate({**template, 'target': target})
            if dispatch.state != 'reserved':
                if claim_owner is not None and await self.run_store.get(dispatch.run_id) is not None:
                    run_ids.append(dispatch.run_id)
                else:
                    skipped_targets.append(target)
                continue
            run_id = dispatch.run_id
            existing = await self.run_store.get(run_id)
            if existing is None:
                try:
                    await self.run_store.create(run_request, run_id=run_id)
                except Exception as error:  # Preserve idempotency if create partially succeeded.
                    existing = await self.run_store.get(run_id)
                    if existing is None:
                        message = f'{target}: {type(error).__name__}: {error}'
                        await self.schedule_store.set_dispatch_state(run_id, 'failed', message)
                        errors.append(message)
                        continue
            await self.schedule_store.set_dispatch_state(run_id, 'queued')
            run_ids.append(run_id)
            if index % 100 == 0:
                if claim_owner is not None and not await self.schedule_store.renew_claim(
                    schedule.schedule_id,
                    claim_owner,
                ):
                    raise RuntimeError('Scheduler lost its occurrence claim while enqueueing targets')
                await asyncio.sleep(0)

        if run_ids:
            run_worker.wake_worker()
        return ScheduleDispatchResponse(
            schedule_id=schedule.schedule_id,
            scheduled_for=utc_iso(scheduled_for),
            run_ids=run_ids,
            skipped_targets=skipped_targets,
            errors=errors,
        )


async def _wait_for_work(store: ScheduleStore) -> None:
    assert _scheduler_wakeup is not None
    _scheduler_wakeup.clear()
    next_due = await store.next_due_at()
    if next_due is None:
        timeout = 5.0
    else:
        timeout = max(0.5, min(5.0, (next_due - utc_now_datetime()).total_seconds()))
    try:
        await asyncio.wait_for(_scheduler_wakeup.wait(), timeout=timeout)
    except TimeoutError:
        pass


async def _scheduler_loop(owner_id: str) -> None:
    assert _scheduler_stop is not None
    store = ScheduleStore()
    dispatcher = ScheduleDispatcher(store, RunStore())
    await store.initialize()
    while not _scheduler_stop.is_set():
        claimed = await store.claim_due(owner_id, limit=1)
        if claimed:
            for schedule in claimed:
                if _scheduler_stop.is_set():
                    break
                try:
                    await dispatcher.dispatch_claimed(schedule, owner_id)
                except Exception as error:
                    await store.defer_claim(
                        schedule.schedule_id,
                        owner_id,
                        seconds=60,
                        error=f'{type(error).__name__}: {error}',
                    )
            continue
        await _wait_for_work(store)


async def start_scheduler() -> None:
    global _scheduler_owner, _scheduler_stop, _scheduler_task, _scheduler_wakeup
    if not scheduler_enabled():
        return
    if _scheduler_task is not None and not _scheduler_task.done():
        return
    owner_id = str(uuid4())
    _scheduler_owner = owner_id
    _scheduler_stop = asyncio.Event()
    _scheduler_wakeup = asyncio.Event()
    _scheduler_task = asyncio.create_task(_scheduler_loop(owner_id))


async def stop_scheduler() -> None:
    global _scheduler_owner, _scheduler_stop, _scheduler_task, _scheduler_wakeup
    task = _scheduler_task
    owner_id = _scheduler_owner
    try:
        if task is not None:
            if _scheduler_stop is not None:
                _scheduler_stop.set()
            if _scheduler_wakeup is not None:
                _scheduler_wakeup.set()
            await task
    finally:
        if owner_id is not None:
            await ScheduleStore().release_claims(owner_id)
        _scheduler_task = None
        _scheduler_owner = None
        _scheduler_stop = None
        _scheduler_wakeup = None
