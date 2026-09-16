from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
from argparse import ArgumentParser
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4
from weakref import WeakKeyDictionary

from .run_artifacts import ensure_private_directory, read_child_evidence, write_child_evidence
from .run_store import RunStore

ProcessFactory = Callable[[str, Path, Path], Awaitable[asyncio.subprocess.Process]]
RunStoreFactory = Callable[[], RunStore]
EnabledCheck = Callable[[], bool]
_LOGGER = logging.getLogger(__name__)


def _log_task_failure(task: asyncio.Task[None]) -> None:
    """Report a crashed supervisor as soon as the task finishes."""
    if task.cancelled():
        return
    error = task.exception()
    if error is not None:
        _LOGGER.error(
            '%s exited unexpectedly',
            task.get_name(),
            exc_info=(type(error), error, error.__traceback__),
        )


class RunWorkerService(Protocol):
    """Worker capabilities used by the runtime, routes, and scheduler."""

    @property
    def enabled(self) -> bool: ...

    @property
    def available(self) -> bool: ...

    def wake(self) -> None: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


@dataclass(slots=True)
class _WorkerSession:
    """Loop-bound state for one started worker instance."""

    store: RunStore
    owner_id: str
    stop_event: asyncio.Event
    wakeup_event: asyncio.Event
    task: asyncio.Task[None] | None = None


def _enabled_from_environment() -> bool:
    return os.getenv('THEHARVESTER_RUN_WORKER', 'enabled').casefold() != 'disabled'


async def _process_output(process: asyncio.subprocess.Process) -> str:
    async def read(stream: asyncio.StreamReader | None) -> bytes:
        return await stream.read() if stream is not None else b''

    stdout, stderr = await asyncio.gather(read(process.stdout), read(process.stderr))
    return '\n'.join(part.decode('utf-8', errors='replace').strip() for part in (stdout, stderr) if part).strip()


class RunWorker:
    """Own the durable-queue worker lifecycle for one FastAPI application.

    The previous implementation kept the task, events, lease owner, process
    factory, and process-group registry in module globals. Keeping those values
    on this instance makes ownership explicit, isolates app/test lifecycles, and
    lets dependencies be injected without monkeypatching module internals.
    """

    def __init__(
        self,
        *,
        process_factory: ProcessFactory | None = None,
        store_factory: RunStoreFactory = RunStore,
        enabled_check: EnabledCheck = _enabled_from_environment,
    ) -> None:
        self._custom_process_factory = process_factory
        self._store_factory = store_factory
        self._enabled_check = enabled_check
        self._session: _WorkerSession | None = None
        self._process_groups: WeakKeyDictionary[asyncio.subprocess.Process, int] = WeakKeyDictionary()

    @property
    def enabled(self) -> bool:
        return self._enabled_check()

    @property
    def available(self) -> bool:
        session = self._session
        return session is not None and session.task is not None and not session.task.done()

    async def start(self) -> None:
        if not self.enabled:
            return
        if self.available:
            return
        if self._session is not None:
            await self.stop()

        session = _WorkerSession(
            store=self._store_factory(),
            owner_id=str(uuid4()),
            stop_event=asyncio.Event(),
            wakeup_event=asyncio.Event(),
        )
        self._session = session
        session.task = asyncio.create_task(
            self._supervise_worker(session),
            name=f'theharvester-run-worker-{session.owner_id}',
        )
        session.task.add_done_callback(_log_task_failure)

    async def stop(self) -> None:
        session = self._session
        if session is None:
            return
        task = session.task
        try:
            session.stop_event.set()
            session.wakeup_event.set()
            if task is not None:
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise
        finally:
            try:
                await session.store.release_worker_lease(session.owner_id)
            finally:
                if self._session is session:
                    self._session = None

    def wake(self) -> None:
        session = self._session
        if session is not None:
            session.wakeup_event.set()

    async def _default_process_factory(
        self,
        run_id: str,
        database: Path,
        _artifact_dir_path: Path,
    ) -> asyncio.subprocess.Process:
        command = (
            sys.executable,
            '-m',
            'theHarvester.lib.api.run_worker',
            '--execute',
            run_id,
            '--database',
            str(database),
        )
        if os.name == 'nt':
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        if process.pid is not None:
            self._process_groups[process] = process.pid
        return process

    async def _spawn_process(self, run_id: str, database: Path, artifact_dir: Path) -> asyncio.subprocess.Process:
        factory = self._custom_process_factory
        if factory is not None:
            return await factory(run_id, database, artifact_dir)
        return await self._default_process_factory(run_id, database, artifact_dir)

    async def _signal_process_tree(self, process: asyncio.subprocess.Process, *, force: bool) -> None:
        process_group = self._process_groups.get(process)
        if process_group is not None and os.name != 'nt':
            try:
                os.killpg(process_group, signal.SIGKILL if force else signal.SIGTERM)
            except ProcessLookupError:
                pass
            return
        if process_group is not None and os.name == 'nt':
            if force:
                killer = await asyncio.create_subprocess_exec(
                    'taskkill',
                    '/PID',
                    str(process.pid),
                    '/T',
                    '/F',
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
            else:
                try:
                    process.send_signal(getattr(signal, 'CTRL_BREAK_EVENT', 1))
                except ProcessLookupError:
                    pass
            return
        try:
            process.kill() if force else process.terminate()
        except ProcessLookupError:
            pass

    async def _stop_process(self, process: asyncio.subprocess.Process, wait_task: asyncio.Task[int]) -> None:
        if process.returncode is None:
            await self._signal_process_tree(process, force=False)
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=2)
        except TimeoutError:
            if process.returncode is None:
                await self._signal_process_tree(process, force=True)
            await wait_task

    async def _abort_process_execution(
        self,
        process: asyncio.subprocess.Process,
        wait_task: asyncio.Task[int] | None,
        output_task: asyncio.Task[str] | None,
    ) -> None:
        """Terminate a child and consume its helper tasks after an exceptional exit."""
        if wait_task is None:
            wait_task = asyncio.create_task(process.wait())
        try:
            await self._stop_process(process, wait_task)
        finally:
            tasks = [task for task in (wait_task, output_task) if task is not None]
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def execute_claimed(
        self,
        store: RunStore,
        run: dict[str, Any],
        owner_id: str | None = None,
        *,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        run_id = run['run_id']
        artifact_dir = store.artifact_directory(run_id)
        ensure_private_directory(artifact_dir)
        try:
            process = await self._spawn_process(run_id, store.database, artifact_dir)
        except (OSError, RuntimeError) as error:
            await store.fail(run_id, f'Could not start child process: {error}', '')
            return

        wait_task: asyncio.Task[int] | None = None
        output_task: asyncio.Task[str] | None = None
        try:
            wait_task = asyncio.create_task(process.wait())
            output_task = asyncio.create_task(_process_output(process))
            deadline_seconds = run['request'].get('deadline_seconds')
            deadline = None if deadline_seconds is None else asyncio.get_running_loop().time() + int(deadline_seconds)
            next_heartbeat = 0.0
            while not wait_task.done():
                await asyncio.sleep(0.05)
                if owner_id is not None and asyncio.get_running_loop().time() >= next_heartbeat:
                    if not await store.heartbeat_worker_lease(owner_id):
                        await self._stop_process(process, wait_task)
                        await store.fail(run_id, 'Worker lost its execution lease', await output_task)
                        return
                    next_heartbeat = asyncio.get_running_loop().time() + 5
                current = await store.get(run_id)
                stopping = stop_event is not None and stop_event.is_set()
                if current is not None and current['status'] == 'cancelling':
                    await self._stop_process(process, wait_task)
                    evidence, evidence_error = read_child_evidence(artifact_dir, str(run['target']))
                    failure_message = 'Cancelled by operator' + (f'; {evidence_error}' if evidence_error else '')
                    await store.fail(run_id, failure_message, await output_task, cancelled=True, evidence=evidence)
                    return
                if stopping:
                    await self._stop_process(process, wait_task)
                    evidence, evidence_error = read_child_evidence(artifact_dir, str(run['target']))
                    failure_message = 'theHarvester stopped before child completion' + (
                        f'; {evidence_error}' if evidence_error else ''
                    )
                    await store.fail(run_id, failure_message, await output_task, evidence=evidence)
                    return
                if deadline is not None and asyncio.get_running_loop().time() >= deadline:
                    await self._stop_process(process, wait_task)
                    evidence, evidence_error = read_child_evidence(artifact_dir, str(run['target']))
                    failure_message = f'Run exceeded its {deadline_seconds} second deadline'
                    if evidence_error:
                        failure_message += f'; {evidence_error}'
                    await store.fail(
                        run_id,
                        failure_message,
                        await output_task,
                        evidence=evidence,
                    )
                    return
            log = await output_task
            current = await store.get(run_id)
            evidence, evidence_error = read_child_evidence(artifact_dir, str(run['target']))
            if evidence_error:
                await store.fail(
                    run_id,
                    evidence_error,
                    log,
                    cancelled=current is not None and current['status'] == 'cancelling',
                )
                return
            if current is not None and current['status'] == 'cancelling':
                await store.finish(run_id, evidence, log)
            elif process.returncode == 0 and evidence is not None:
                await store.finish(run_id, evidence, log)
            else:
                await store.fail(
                    run_id,
                    f'Child process exited with status {process.returncode} without terminal completion',
                    log,
                    evidence=evidence,
                )
        except asyncio.CancelledError:
            await self._abort_process_execution(process, wait_task, output_task)
            raise
        except BaseException:
            await self._abort_process_execution(process, wait_task, output_task)
            raise
        finally:
            self._process_groups.pop(process, None)

    async def _worker_loop(self, session: _WorkerSession) -> None:
        while not session.stop_event.is_set():
            if not await session.store.heartbeat_worker_lease(session.owner_id):
                return
            run = await session.store.claim_next()
            if run is not None:
                await self.execute_claimed(
                    session.store,
                    run,
                    session.owner_id,
                    stop_event=session.stop_event,
                )
                continue
            session.wakeup_event.clear()
            try:
                await asyncio.wait_for(session.wakeup_event.wait(), timeout=0.5)
            except TimeoutError:
                continue

    async def _supervise_worker(self, session: _WorkerSession) -> None:
        while not session.stop_event.is_set():
            if await session.store.acquire_worker_lease(session.owner_id):
                try:
                    await session.store.recover_orphans()
                except BaseException:
                    await session.store.release_worker_lease(session.owner_id)
                    raise
                await self._worker_loop(session)
                return
            session.wakeup_event.clear()
            try:
                await asyncio.wait_for(session.wakeup_event.wait(), timeout=0.5)
            except TimeoutError:
                continue


async def _child_execute(run_id: str, database: Path) -> None:
    import anyio

    from theHarvester import __main__ as main_module
    from theHarvester.lib.completed_result import CompletedResult
    from theHarvester.lib.enumeration import (
        DEFAULT_RESULT_START,
        DEFAULT_SOURCE_WORKERS,
        EnumerationOptions,
    )
    from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS
    from theHarvester.lib.virtual_host import (
        DEFAULT_VHOST_CONCURRENCY,
        DEFAULT_VHOST_REQUEST_LIMIT,
        DEFAULT_VHOST_RUNTIME_SECONDS,
        DEFAULT_VHOST_TIMEOUT_SECONDS,
    )

    store = RunStore(database)
    run = await store.get(run_id)
    if run is None or run['status'] not in {'running', 'cancelling'}:
        raise RuntimeError('theHarvester run is not executable')
    request = run['request']
    artifact_dir = store.artifact_directory(run_id)
    ensure_private_directory(artifact_dir)
    screenshot_dir = artifact_dir / 'screenshots'
    if request.get('screenshot'):
        ensure_private_directory(screenshot_dir)
    recursive_depth = request.get('dns_recursive_depth', 0)
    resolver_list = request.get('dns_resolvers', list(DEFAULT_DNS_RESOLVERS))
    api_scan_wordlist = ''
    if request.get('api_scan_paths'):
        api_scan_wordlist_path = artifact_dir / 'api-scan-paths.txt'
        await anyio.Path(api_scan_wordlist_path).write_text(
            ''.join(f'{path}\n' for path in request['api_scan_paths']),
            encoding='utf-8',
        )
        api_scan_wordlist = str(api_scan_wordlist_path)
    args = EnumerationOptions(
        api_scan=request.get('api_scan', False),
        dns_brute=request.get('dns_brute', False),
        dns_lookup=request.get('dns_lookup', False),
        dns_recursive_depth=recursive_depth,
        dns_recursive_query_limit=request.get('dns_recursive_query_limit'),
        dns_recursive_runtime_seconds=request.get('dns_recursive_runtime_seconds'),
        dns_resolve=','.join(resolver_list) if request.get('dns_resolve') else '',
        dns_resolvers=tuple(resolver_list),
        domain=run['target'],
        filename='',
        limit=request['limit'],
        no_hosts=request.get('no_hosts', False),
        proxies=request.get('proxies', False),
        quiet=True,
        routeviews=request.get('routeviews', False),
        screenshot=str(screenshot_dir) if request.get('screenshot') else '',
        shodan=request.get('shodan', False),
        source=','.join(request['sources']),
        source_workers=request.get('source_workers', DEFAULT_SOURCE_WORKERS),
        start=request.get('start', DEFAULT_RESULT_START),
        take_over=request.get('takeover', False),
        vhost=request.get('vhost', False),
        vhost_candidates=tuple(request.get('vhost_candidates', ())),
        vhost_concurrency=request.get('vhost_concurrency', DEFAULT_VHOST_CONCURRENCY),
        vhost_endpoint=request.get('vhost_endpoint', ''),
        vhost_insecure=request.get('vhost_insecure', False),
        vhost_request_limit=request.get('vhost_request_limit', DEFAULT_VHOST_REQUEST_LIMIT),
        vhost_runtime_seconds=request.get('vhost_runtime_seconds', DEFAULT_VHOST_RUNTIME_SECONDS),
        vhost_timeout_seconds=request.get('vhost_timeout_seconds', DEFAULT_VHOST_TIMEOUT_SECONDS),
        wordlist=api_scan_wordlist,
    )
    checkpoint_lock = asyncio.Lock()

    async def checkpoint(evidence: CompletedResult) -> None:
        async with checkpoint_lock:
            write_child_evidence(artifact_dir, evidence, partial=True)

    task = asyncio.create_task(
        main_module.start(
            args,
            completed_result_checkpoint=checkpoint,
            return_completed_result=True,
            result_database=database,
            completed_run_id=UUID(run_id),
        )
    )
    loop = asyncio.get_running_loop()
    signal_handler_installed = False
    if os.name != 'nt':
        try:
            loop.add_signal_handler(signal.SIGTERM, task.cancel)
            signal_handler_installed = True
        except NotImplementedError, RuntimeError:
            pass
    try:
        response = await task
    except asyncio.CancelledError:
        return
    finally:
        if signal_handler_installed:
            loop.remove_signal_handler(signal.SIGTERM)
    evidence = response[-1]
    if not isinstance(evidence, CompletedResult):
        raise RuntimeError('theHarvester did not return terminal evidence')
    write_child_evidence(artifact_dir, evidence, partial=False)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--execute', required=True)
    parser.add_argument('--database', required=True, type=Path)
    child_args = parser.parse_args()
    asyncio.run(_child_execute(child_args.execute, child_args.database))
