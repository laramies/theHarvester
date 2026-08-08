from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import aiosqlite
from fastapi import HTTPException, status

from .run_artifacts import RunPaths, read_child_evidence
from .run_models import RunRequest, _normalize_target, utc_now
from .run_projection import (
    activities_for_evidence,
    activities_for_request,
    normalized_results,
    screenshots,
    source_executions,
)

if TYPE_CHECKING:
    from pathlib import Path

WORKER_LEASE_TIMEOUT_SECONDS = 30


class RunStore:
    def __init__(self, database: str | Path | None = None) -> None:
        self.paths = RunPaths.configured(database)
        self.database = self.paths.database

    def artifact_directory(self, run_id: str) -> Path:
        return self.paths.artifact_directory(run_id)

    async def initialize(self) -> None:
        try:
            self.database.parent.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            pass
        else:
            self.database.parent.chmod(0o700)
        self.database.touch(exist_ok=True, mode=0o600)
        self.database.chmod(0o600)
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    request_json TEXT NOT NULL,
                    evidence_json TEXT,
                    cancellation_requested_at TEXT,
                    error TEXT,
                    log TEXT NOT NULL DEFAULT ''
                )
                """
            )
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS run_worker_lease (
                    lease_name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL
                )
                """
            )
            await database.commit()

    def _row(self, row: aiosqlite.Row, *, detail: bool = False) -> dict[str, Any]:
        result = {
            'run_id': row['run_id'],
            'target': row['target'],
            'status': row['status'],
            'origin': row['origin'],
            'created_at': row['created_at'],
            'started_at': row['started_at'],
            'completed_at': row['completed_at'],
            'cancellation_requested_at': row['cancellation_requested_at'],
            'error': row['error'],
        }
        request = json.loads(row['request_json'])
        evidence = json.loads(row['evidence_json']) if row['evidence_json'] else None
        result['sources'] = request.get('sources', [])
        result['activities'] = activities_for_request(request)
        result['evidence_status'] = evidence.get('status') if evidence else None
        result['result_count'] = len(normalized_results(evidence)) if evidence else 0
        if detail:
            result['request'] = request
            result['evidence'] = evidence
            result['results'] = normalized_results(evidence)
            result['source_executions'] = source_executions(evidence)
            result['screenshots'] = screenshots(evidence, row['run_id'], self.artifact_directory(row['run_id']))
            result['log'] = row['log']
        return result

    async def create(self, request: RunRequest) -> dict[str, Any]:
        await self.initialize()
        run_id = str(uuid4())
        created_at = utc_now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                INSERT INTO runs
                    (run_id, target, status, origin, created_at, request_json)
                VALUES (?, ?, 'queued', 'local', ?, ?)
                """,
                (run_id, request.target, created_at, request.model_dump_json()),
            )
            await database.commit()
        run = await self.get(run_id)
        assert run is not None
        return run

    async def import_evidence(self, evidence: dict[str, Any], filename: str) -> dict[str, Any]:
        await self.initialize()
        run_id = str(uuid4())
        created_at = utc_now()
        target = _normalize_target(str(evidence['target']))
        executions = source_executions(evidence)
        request = {
            'filename': filename,
            'sources': sorted(
                {
                    str(execution.get('source') or execution.get('name'))
                    for execution in executions
                    if execution.get('source') or execution.get('name')
                }
            ),
            'activities': activities_for_evidence(executions),
        }
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                INSERT INTO runs
                    (run_id, target, status, origin, created_at, started_at, completed_at, request_json, evidence_json)
                VALUES (?, ?, 'completed', 'imported', ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target,
                    created_at,
                    evidence.get('started_at'),
                    evidence.get('completed_at') or created_at,
                    json.dumps(request),
                    json.dumps(evidence),
                ),
            )
            await database.commit()
        run = await self.get(run_id)
        assert run is not None
        return run

    async def list_runs(self) -> list[dict[str, Any]]:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            database.row_factory = aiosqlite.Row
            cursor = await database.execute('SELECT * FROM runs ORDER BY created_at DESC')
            rows = await cursor.fetchall()
        return [self._row(row) for row in rows]

    async def get(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            database.row_factory = aiosqlite.Row
            cursor = await database.execute('SELECT * FROM runs WHERE run_id = ?', (run_id,))
            row = await cursor.fetchone()
        return self._row(row, detail=True) if row else None

    async def cancel(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        requested_at = utc_now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute('SELECT status FROM runs WHERE run_id = ?', (run_id,))
            row = await cursor.fetchone()
            if row is None:
                await database.rollback()
                return None
            current = row[0]
            if current == 'queued':
                await database.execute(
                    "UPDATE runs SET status = 'cancelled', cancellation_requested_at = ?, completed_at = ? "
                    "WHERE run_id = ? AND status = 'queued'",
                    (requested_at, requested_at, run_id),
                )
            elif current == 'running':
                await database.execute(
                    "UPDATE runs SET status = 'cancelling', cancellation_requested_at = ? "
                    "WHERE run_id = ? AND status = 'running'",
                    (requested_at, run_id),
                )
            elif current not in {'cancelling', 'cancelled'}:
                await database.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f'Run is already {current}')
            await database.commit()
        return await self.get(run_id)

    async def recover_orphans(self) -> None:
        await self.initialize()
        recovered_at = utc_now()
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute("SELECT run_id FROM runs WHERE status IN ('running', 'cancelling')")
            for (run_id,) in await cursor.fetchall():
                evidence, evidence_error = read_child_evidence(self.artifact_directory(run_id))
                error = 'theHarvester restarted before child completion'
                if evidence_error:
                    error += f'; {evidence_error}'
                await database.execute(
                    """
                    UPDATE runs
                    SET status = 'failed', completed_at = ?, error = ?, evidence_json = COALESCE(?, evidence_json)
                    WHERE run_id = ? AND status IN ('running', 'cancelling')
                    """,
                    (recovered_at, error, json.dumps(evidence) if evidence else None, run_id),
                )
            await database.commit()

    async def acquire_worker_lease(self, owner_id: str) -> bool:
        await self.initialize()
        now = utc_now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute("SELECT owner_id, heartbeat_at FROM run_worker_lease WHERE lease_name = 'executor'")
            row = await cursor.fetchone()
            stale = row is not None and datetime.fromisoformat(row[1]) < datetime.fromisoformat(now) - timedelta(
                seconds=WORKER_LEASE_TIMEOUT_SECONDS
            )
            if row is not None and row[0] != owner_id and not stale:
                await database.rollback()
                return False
            await database.execute(
                """
                INSERT INTO run_worker_lease (lease_name, owner_id, heartbeat_at)
                VALUES ('executor', ?, ?)
                ON CONFLICT(lease_name) DO UPDATE
                SET owner_id = excluded.owner_id, heartbeat_at = excluded.heartbeat_at
                """,
                (owner_id, now),
            )
            await database.commit()
        return True

    async def heartbeat_worker_lease(self, owner_id: str) -> bool:
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute(
                "UPDATE run_worker_lease SET heartbeat_at = ? WHERE lease_name = 'executor' AND owner_id = ?",
                (utc_now(), owner_id),
            )
            await database.commit()
        return cursor.rowcount == 1

    async def release_worker_lease(self, owner_id: str) -> None:
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                "DELETE FROM run_worker_lease WHERE lease_name = 'executor' AND owner_id = ?",
                (owner_id,),
            )
            await database.commit()

    async def claim_next(self) -> dict[str, Any] | None:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute("SELECT run_id FROM runs WHERE status = 'queued' ORDER BY created_at LIMIT 1")
            row = await cursor.fetchone()
            if row is None:
                await database.rollback()
                return None
            run_id = row[0]
            started_at = utc_now()
            cursor = await database.execute(
                "UPDATE runs SET status = 'running', started_at = ? WHERE run_id = ? AND status = 'queued'",
                (started_at, run_id),
            )
            if cursor.rowcount != 1:
                await database.rollback()
                return None
            await database.commit()
        return await self.get(run_id)

    async def finish(self, run_id: str, evidence: dict[str, Any] | None, log: str) -> None:
        completed_at = utc_now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                UPDATE runs
                SET status = CASE status WHEN 'cancelling' THEN 'cancelled' ELSE 'completed' END,
                    completed_at = ?, evidence_json = COALESCE(?, evidence_json), log = ?
                WHERE run_id = ? AND status IN ('running', 'cancelling')
                """,
                (completed_at, json.dumps(evidence) if evidence else None, log[-200_000:], run_id),
            )
            await database.commit()

    async def fail(
        self,
        run_id: str,
        error: str,
        log: str,
        *,
        cancelled: bool = False,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        completed_at = utc_now()
        lifecycle_status = 'cancelled' if cancelled else 'failed'
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                'UPDATE runs SET status = ?, completed_at = ?, error = ?, log = ?, '
                'evidence_json = COALESCE(?, evidence_json) WHERE run_id = ?',
                (lifecycle_status, completed_at, error, log[-200_000:], json.dumps(evidence) if evidence else None, run_id),
            )
            await database.commit()
