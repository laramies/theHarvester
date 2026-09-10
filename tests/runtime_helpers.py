from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from theHarvester.lib.api.run_worker import RunWorker, RunWorkerService
from theHarvester.lib.api.runtime import ApiRuntime
from theHarvester.lib.api.schedule_service import SchedulerService

if TYPE_CHECKING:
    from theHarvester.lib.api.run_worker import ProcessFactory


@dataclass
class StaticRunWorker:
    """Small explicit worker test double; no module state or monkeypatching required."""

    enabled: bool = True
    available: bool = True
    wake_count: int = 0
    start_count: int = 0
    stop_count: int = 0

    async def start(self) -> None:
        self.start_count += 1

    async def stop(self) -> None:
        self.stop_count += 1

    def wake(self) -> None:
        self.wake_count += 1


def static_runtime(*, enabled: bool = True, available: bool = True) -> ApiRuntime:
    worker = StaticRunWorker(enabled=enabled, available=available)
    scheduler = SchedulerService(worker, enabled_check=lambda: False)
    return ApiRuntime(worker=worker, scheduler=scheduler)


def runtime_with_process_factory(process_factory: ProcessFactory) -> ApiRuntime:
    worker = RunWorker(process_factory=process_factory)
    return ApiRuntime(worker=worker, scheduler=SchedulerService(worker, enabled_check=lambda: False))


def ready_worker() -> RunWorkerService:
    return StaticRunWorker()
