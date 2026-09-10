from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.runtime_helpers import StaticRunWorker, static_runtime
from theHarvester.lib.api.api import create_app
from theHarvester.lib.api.run_worker import RunWorker
from theHarvester.lib.api.runtime import create_runtime
from theHarvester.lib.api.schedule_service import SchedulerService


class _IdleRunStore:
    def __init__(self, name: str) -> None:
        self.database = Path(f'{name}.sqlite')
        self.acquired_owner_ids: list[str] = []
        self.released_owner_ids: list[str] = []
        self.waiting = asyncio.Event()

    async def acquire_worker_lease(self, owner_id: str) -> bool:
        self.acquired_owner_ids.append(owner_id)
        self.waiting.set()
        return False

    async def release_worker_lease(self, owner_id: str) -> None:
        self.released_owner_ids.append(owner_id)


class _IdleScheduleStore:
    def __init__(self) -> None:
        self.claimed_owner_ids: list[str] = []
        self.released_owner_ids: list[str] = []
        self.waiting = asyncio.Event()

    async def initialize(self) -> None:
        return None

    async def claim_due(self, owner_id: str, *, limit: int) -> list[Any]:
        assert limit == 1
        self.claimed_owner_ids.append(owner_id)
        return []

    async def next_due_at(self) -> None:
        self.waiting.set()
        return None

    async def release_claims(self, owner_id: str) -> None:
        self.released_owner_ids.append(owner_id)


class _FailingRunStore:
    def __init__(self) -> None:
        self.database = Path('failing-worker.sqlite')
        self.failed = asyncio.Event()
        self.released_owner_ids: list[str] = []

    async def acquire_worker_lease(self, _owner_id: str) -> bool:
        self.failed.set()
        raise RuntimeError('worker supervisor failed')

    async def release_worker_lease(self, owner_id: str) -> None:
        self.released_owner_ids.append(owner_id)


class _FailingScheduleStore:
    def __init__(self) -> None:
        self.failed = asyncio.Event()
        self.released_owner_ids: list[str] = []

    async def initialize(self) -> None:
        self.failed.set()
        raise RuntimeError('scheduler supervisor failed')

    async def release_claims(self, owner_id: str) -> None:
        self.released_owner_ids.append(owner_id)


def test_worker_instances_do_not_share_lifecycle_state() -> None:
    async def scenario() -> None:
        first_store = _IdleRunStore('first')
        second_store = _IdleRunStore('second')
        first = RunWorker(store_factory=lambda: first_store)
        second = RunWorker(store_factory=lambda: second_store)

        await first.start()
        await second.start()
        await asyncio.gather(first_store.waiting.wait(), second_store.waiting.wait())

        assert first.available is True
        assert second.available is True
        assert first_store.acquired_owner_ids[0] != second_store.acquired_owner_ids[0]

        await first.stop()
        assert first.available is False
        assert second.available is True
        assert first_store.released_owner_ids == first_store.acquired_owner_ids[:1]
        assert second_store.released_owner_ids == []

        await second.stop()
        assert second.available is False
        assert second_store.released_owner_ids == second_store.acquired_owner_ids[:1]

    asyncio.run(scenario())


def test_scheduler_instances_do_not_share_lifecycle_state() -> None:
    async def scenario() -> None:
        first_store = _IdleScheduleStore()
        second_store = _IdleScheduleStore()
        first = SchedulerService(
            StaticRunWorker(),
            schedule_store_factory=lambda: first_store,
            run_store_factory=object,
        )
        second = SchedulerService(
            StaticRunWorker(),
            schedule_store_factory=lambda: second_store,
            run_store_factory=object,
        )

        await first.start()
        await second.start()
        await asyncio.gather(first_store.waiting.wait(), second_store.waiting.wait())

        assert first.available is True
        assert second.available is True
        assert first_store.claimed_owner_ids[0] != second_store.claimed_owner_ids[0]

        await first.stop()
        assert first.available is False
        assert second.available is True
        assert first_store.released_owner_ids == first_store.claimed_owner_ids[:1]
        assert second_store.released_owner_ids == []

        await second.stop()
        assert second.available is False
        assert second_store.released_owner_ids == second_store.claimed_owner_ids[:1]

    asyncio.run(scenario())


def test_runtime_factory_builds_a_fresh_owned_service_graph() -> None:
    first = create_runtime()
    second = create_runtime()

    assert first is not second
    assert first.worker is not second.worker
    assert first.scheduler is not second.scheduler
    assert first.scheduler.worker is first.worker
    assert second.scheduler.worker is second.worker


def test_app_factory_uses_the_injected_runtime_lifecycle() -> None:
    runtime = static_runtime(enabled=True, available=True)
    application = create_app(runtime_factory=lambda: runtime)

    with TestClient(application):
        assert application.state.runtime is runtime
        assert runtime.worker.start_count == 1
        assert runtime.worker.stop_count == 0

    assert application.state.runtime is None
    assert runtime.worker.stop_count == 1


def test_app_factory_lifespans_receive_distinct_runtimes(monkeypatch) -> None:
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
    first_app = create_app()
    second_app = create_app()

    with TestClient(first_app):
        first_runtime = first_app.state.runtime
        assert first_runtime is not None
    assert first_app.state.runtime is None

    with TestClient(second_app):
        second_runtime = second_app.state.runtime
        assert second_runtime is not None
    assert second_app.state.runtime is None

    assert first_runtime is not second_runtime
    assert first_runtime.worker is not second_runtime.worker
    assert first_runtime.scheduler is not second_runtime.scheduler


def test_worker_logs_an_unexpected_supervisor_failure(caplog) -> None:
    async def scenario() -> None:
        store = _FailingRunStore()
        worker = RunWorker(store_factory=lambda: store)

        await worker.start()
        await store.failed.wait()
        while worker.available:
            await asyncio.sleep(0)
        await asyncio.sleep(0)

        with pytest.raises(RuntimeError, match='worker supervisor failed'):
            await worker.stop()
        assert len(store.released_owner_ids) == 1

    with caplog.at_level(logging.ERROR, logger='theHarvester.lib.api.run_worker'):
        asyncio.run(scenario())

    assert 'theharvester-run-worker-' in caplog.text
    assert 'worker supervisor failed' in caplog.text


def test_scheduler_logs_an_unexpected_supervisor_failure(caplog) -> None:
    async def scenario() -> None:
        store = _FailingScheduleStore()
        scheduler = SchedulerService(
            StaticRunWorker(),
            schedule_store_factory=lambda: store,
            run_store_factory=object,
        )

        await scheduler.start()
        await store.failed.wait()
        while scheduler.available:
            await asyncio.sleep(0)
        await asyncio.sleep(0)

        with pytest.raises(RuntimeError, match='scheduler supervisor failed'):
            await scheduler.stop()
        assert len(store.released_owner_ids) == 1

    with caplog.at_level(logging.ERROR, logger='theHarvester.lib.api.schedule_service'):
        asyncio.run(scenario())

    assert 'theharvester-scheduler-' in caplog.text
    assert 'scheduler supervisor failed' in caplog.text
