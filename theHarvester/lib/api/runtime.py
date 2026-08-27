from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request  # noqa: TC002 - FastAPI resolves dependency annotations at runtime

from .run_worker import RunWorker, RunWorkerService
from .schedule_service import SchedulerService


@dataclass(slots=True)
class ApiRuntime:
    """Application-owned background services for one FastAPI lifespan."""

    worker: RunWorkerService
    scheduler: SchedulerService

    async def start(self) -> None:
        await self.worker.start()
        try:
            await self.scheduler.start()
        except BaseException:
            await self.worker.stop()
            raise

    async def stop(self) -> None:
        try:
            await self.scheduler.stop()
        finally:
            await self.worker.stop()


def create_runtime() -> ApiRuntime:
    worker = RunWorker()
    return ApiRuntime(worker=worker, scheduler=SchedulerService(worker))


def get_runtime(request: Request) -> ApiRuntime:
    runtime = getattr(request.app.state, 'runtime', None)
    if not isinstance(runtime, ApiRuntime):
        raise RuntimeError('theHarvester API runtime is not initialized')
    return runtime


def get_run_worker(request: Request) -> RunWorkerService:
    return get_runtime(request).worker


def get_scheduler(request: Request) -> SchedulerService:
    return get_runtime(request).scheduler
