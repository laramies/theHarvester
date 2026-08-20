from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import aiosqlite

from .run_artifacts import RunPaths, ensure_private_directory
from .schedule_models import (
    DispatchState,
    ScheduleCreate,
    ScheduleDispatchRecord,
    ScheduleResponse,
    parse_utc,
    utc_iso,
    utc_now_datetime,
)

_INITIALIZED: set[str] = set()
_INITIALIZE_LOCKS: dict[str, asyncio.Lock] = {}


class ScheduleStoreError(RuntimeError):
    """Persistent schedule state could not be read or updated."""


def configured_schedule_database(run_database: str | Path | None = None) -> Path:
    configured = os.getenv('THEHARVESTER_SCHEDULE_DB')
    if configured:
        return Path(configured).expanduser()
    run_database_path = RunPaths.configured(run_database).database
    return run_database_path.with_name(f'{run_database_path.stem}.schedules.sqlite')


class ScheduleStore:
    """Persist scheduler control-plane state separately from portable run evidence."""

    def __init__(self, database: str | Path | None = None) -> None:
        self.database = configured_schedule_database(database).expanduser().absolute()

    async def _connect(self) -> aiosqlite.Connection:
        if self.database.is_symlink():
            raise ScheduleStoreError(f'Refusing symlinked schedule database: {self.database}')
        connection = await aiosqlite.connect(self.database, timeout=30)
        connection.row_factory = aiosqlite.Row
        await connection.execute('PRAGMA foreign_keys = ON')
        await connection.execute('PRAGMA busy_timeout = 30000')
        return connection

    async def initialize(self) -> None:
        key = str(self.database)
        if key in _INITIALIZED and self.database.exists():
            return
        lock = _INITIALIZE_LOCKS.setdefault(key, asyncio.Lock())
        async with lock:
            if key in _INITIALIZED and self.database.exists():
                return
            ensure_private_directory(self.database.parent)
            if self.database.exists() and self.database.is_symlink():
                raise ScheduleStoreError(f'Refusing symlinked schedule database: {self.database}')
            connection = await self._connect()
            try:
                await connection.execute('PRAGMA journal_mode = WAL')
                await connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schedules (
                        schedule_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        targets_json TEXT NOT NULL,
                        run_json TEXT NOT NULL,
                        timing_json TEXT NOT NULL,
                        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                        overlap_policy TEXT NOT NULL CHECK (overlap_policy IN ('skip', 'queue')),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        next_run_at TEXT,
                        last_run_at TEXT,
                        last_error TEXT,
                        claim_owner TEXT,
                        claim_until TEXT
                    );
                    CREATE INDEX IF NOT EXISTS schedules_due_idx
                        ON schedules (enabled, next_run_at, claim_until);

                    CREATE TABLE IF NOT EXISTS schedule_dispatches (
                        dispatch_id TEXT PRIMARY KEY,
                        schedule_id TEXT NOT NULL,
                        scheduled_for TEXT NOT NULL,
                        target TEXT NOT NULL,
                        run_id TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL CHECK (
                            state IN ('reserved', 'queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled')
                        ),
                        error TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE (schedule_id, scheduled_for, target),
                        FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS schedule_dispatches_schedule_idx
                        ON schedule_dispatches (schedule_id, scheduled_for DESC);
                    CREATE INDEX IF NOT EXISTS schedule_dispatches_pending_idx
                        ON schedule_dispatches (schedule_id, state);
                    """
                )
                await connection.commit()
            except aiosqlite.Error as error:
                raise ScheduleStoreError('Could not initialize schedule database') from error
            finally:
                await connection.close()
            self.database.chmod(0o600)
            _INITIALIZED.add(key)

    @staticmethod
    def _response(row: aiosqlite.Row) -> ScheduleResponse:
        return ScheduleResponse.model_validate(
            {
                'schedule_id': row['schedule_id'],
                'name': row['name'],
                'targets': json.loads(row['targets_json']),
                'run': json.loads(row['run_json']),
                'timing': json.loads(row['timing_json']),
                'enabled': bool(row['enabled']),
                'overlap_policy': row['overlap_policy'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'next_run_at': row['next_run_at'],
                'last_run_at': row['last_run_at'],
                'last_error': row['last_error'],
            }
        )

    async def create(self, request: ScheduleCreate) -> ScheduleResponse:
        await self.initialize()
        now = utc_now_datetime()
        now_text = utc_iso(now)
        schedule_id = str(uuid4())
        next_run_at = utc_iso(request.timing.first_due_at()) if request.enabled else None
        connection = await self._connect()
        try:
            await connection.execute(
                'INSERT INTO schedules '
                '(schedule_id, name, targets_json, run_json, timing_json, enabled, overlap_policy, created_at, '
                'updated_at, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    schedule_id,
                    request.name,
                    json.dumps(request.targets, separators=(',', ':')),
                    request.run.model_dump_json(),
                    request.timing.model_dump_json(),
                    int(request.enabled),
                    request.overlap_policy,
                    now_text,
                    now_text,
                    next_run_at,
                ),
            )
            await connection.commit()
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not create schedule') from error
        finally:
            await connection.close()
        created = await self.get(schedule_id)
        assert created is not None
        return created

    async def list_schedules(self, *, limit: int = 100, offset: int = 0) -> list[ScheduleResponse]:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'SELECT * FROM schedules ORDER BY created_at DESC LIMIT ? OFFSET ?',
                (limit, offset),
            )
            return [self._response(row) for row in await cursor.fetchall()]
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not list schedules') from error
        finally:
            await connection.close()

    async def get(self, schedule_id: str) -> ScheduleResponse | None:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute('SELECT * FROM schedules WHERE schedule_id = ?', (schedule_id,))
            row = await cursor.fetchone()
            return self._response(row) if row is not None else None
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not read schedule') from error
        finally:
            await connection.close()

    async def replace(self, schedule_id: str, request: ScheduleCreate) -> ScheduleResponse | None:
        await self.initialize()
        now_text = utc_iso(utc_now_datetime())
        next_run_at = utc_iso(request.timing.first_due_at()) if request.enabled else None
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'UPDATE schedules SET name = ?, targets_json = ?, run_json = ?, timing_json = ?, enabled = ?, '
                'overlap_policy = ?, updated_at = ?, next_run_at = ?, last_run_at = NULL, last_error = NULL, '
                'claim_owner = NULL, '
                'claim_until = NULL WHERE schedule_id = ?',
                (
                    request.name,
                    json.dumps(request.targets, separators=(',', ':')),
                    request.run.model_dump_json(),
                    request.timing.model_dump_json(),
                    int(request.enabled),
                    request.overlap_policy,
                    now_text,
                    next_run_at,
                    schedule_id,
                ),
            )
            await connection.commit()
            if cursor.rowcount == 0:
                return None
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not update schedule') from error
        finally:
            await connection.close()
        return await self.get(schedule_id)

    async def set_enabled(self, schedule_id: str, enabled: bool) -> ScheduleResponse | None:
        await self.initialize()
        existing = await self.get(schedule_id)
        if existing is None:
            return None
        now = utc_now_datetime()
        if enabled:
            if existing.timing.frequency == 'once' and existing.last_run_at is not None:
                next_run_at = None
            elif existing.last_run_at is None:
                next_run_at = utc_iso(existing.timing.first_due_at())
            else:
                next_value = existing.timing.next_after(now - timedelta(microseconds=1))
                next_run_at = utc_iso(next_value) if next_value is not None else None
        else:
            next_run_at = None
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'UPDATE schedules SET enabled = ?, updated_at = ?, next_run_at = ?, claim_owner = NULL, '
                'claim_until = NULL WHERE schedule_id = ?',
                (int(enabled), utc_iso(now), next_run_at, schedule_id),
            )
            await connection.commit()
            if cursor.rowcount == 0:
                return None
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not change schedule state') from error
        finally:
            await connection.close()
        return await self.get(schedule_id)

    async def delete(self, schedule_id: str) -> bool:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute('DELETE FROM schedules WHERE schedule_id = ?', (schedule_id,))
            await connection.commit()
            return cursor.rowcount > 0
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not delete schedule') from error
        finally:
            await connection.close()

    async def next_due_at(self) -> datetime | None:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'SELECT MIN(next_run_at) AS next_run_at FROM schedules WHERE enabled = 1 AND next_run_at IS NOT NULL'
            )
            row = await cursor.fetchone()
            return parse_utc(row['next_run_at']) if row is not None and row['next_run_at'] else None
        finally:
            await connection.close()

    async def claim_due(
        self,
        owner_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 60,
        limit: int = 10,
    ) -> list[ScheduleResponse]:
        await self.initialize()
        current = (now or utc_now_datetime()).astimezone(UTC)
        now_text = utc_iso(current)
        claim_until = utc_iso(current + timedelta(seconds=lease_seconds))
        connection = await self._connect()
        try:
            await connection.execute('BEGIN IMMEDIATE')
            cursor = await connection.execute(
                'SELECT schedule_id FROM schedules WHERE enabled = 1 AND next_run_at IS NOT NULL '
                'AND next_run_at <= ? AND (claim_until IS NULL OR claim_until < ?) '
                'ORDER BY next_run_at, schedule_id LIMIT ?',
                (now_text, now_text, limit),
            )
            schedule_ids = [row['schedule_id'] for row in await cursor.fetchall()]
            claimed: list[ScheduleResponse] = []
            for schedule_id in schedule_ids:
                update = await connection.execute(
                    'UPDATE schedules SET claim_owner = ?, claim_until = ? WHERE schedule_id = ? '
                    'AND enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? '
                    'AND (claim_until IS NULL OR claim_until < ?)',
                    (owner_id, claim_until, schedule_id, now_text, now_text),
                )
                if update.rowcount:
                    row_cursor = await connection.execute('SELECT * FROM schedules WHERE schedule_id = ?', (schedule_id,))
                    row = await row_cursor.fetchone()
                    if row is not None:
                        claimed.append(self._response(row))
            await connection.commit()
            return claimed
        except aiosqlite.Error as error:
            await connection.rollback()
            raise ScheduleStoreError('Could not claim due schedules') from error
        finally:
            await connection.close()

    async def renew_claim(self, schedule_id: str, owner_id: str, *, lease_seconds: int = 60) -> bool:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'UPDATE schedules SET claim_until = ? WHERE schedule_id = ? AND claim_owner = ?',
                (utc_iso(utc_now_datetime() + timedelta(seconds=lease_seconds)), schedule_id, owner_id),
            )
            await connection.commit()
            return cursor.rowcount > 0
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not renew schedule claim') from error
        finally:
            await connection.close()

    async def complete_claim(
        self,
        schedule_id: str,
        owner_id: str,
        *,
        scheduled_for: datetime,
        next_run_at: datetime | None,
        error: str | None = None,
    ) -> bool:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'UPDATE schedules SET last_run_at = ?, next_run_at = ?, last_error = ?, updated_at = ?, '
                'claim_owner = NULL, claim_until = NULL WHERE schedule_id = ? AND claim_owner = ?',
                (
                    utc_iso(scheduled_for),
                    utc_iso(next_run_at) if next_run_at is not None else None,
                    error,
                    utc_iso(utc_now_datetime()),
                    schedule_id,
                    owner_id,
                ),
            )
            await connection.commit()
            return cursor.rowcount > 0
        except aiosqlite.Error as store_error:
            raise ScheduleStoreError('Could not complete schedule claim') from store_error
        finally:
            await connection.close()

    async def defer_claim(self, schedule_id: str, owner_id: str, *, seconds: int, error: str) -> bool:
        await self.initialize()
        now = utc_now_datetime()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'UPDATE schedules SET last_error = ?, updated_at = ?, claim_owner = NULL, claim_until = ? '
                'WHERE schedule_id = ? AND claim_owner = ?',
                (error, utc_iso(now), utc_iso(now + timedelta(seconds=seconds)), schedule_id, owner_id),
            )
            await connection.commit()
            return cursor.rowcount > 0
        except aiosqlite.Error as store_error:
            raise ScheduleStoreError('Could not defer schedule claim') from store_error
        finally:
            await connection.close()

    async def reserve_dispatch(
        self,
        schedule_id: str,
        scheduled_for: datetime,
        target: str,
        run_id: str,
    ) -> ScheduleDispatchRecord | None:
        await self.initialize()
        now_text = utc_iso(utc_now_datetime())
        dispatch_id = str(uuid4())
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'INSERT OR IGNORE INTO schedule_dispatches '
                '(dispatch_id, schedule_id, scheduled_for, target, run_id, state, created_at, updated_at) '
                "VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?)",
                (dispatch_id, schedule_id, utc_iso(scheduled_for), target, run_id, now_text, now_text),
            )
            await connection.commit()
            if cursor.rowcount == 0:
                existing_cursor = await connection.execute(
                    'SELECT * FROM schedule_dispatches WHERE schedule_id = ? AND scheduled_for = ? AND target = ?',
                    (schedule_id, utc_iso(scheduled_for), target),
                )
                existing = await existing_cursor.fetchone()
                return ScheduleDispatchRecord.model_validate(dict(existing)) if existing is not None else None
        except aiosqlite.Error as error:
            raise ScheduleStoreError('Could not reserve scheduled run') from error
        finally:
            await connection.close()
        return await self.get_dispatch(dispatch_id)

    async def get_dispatch(self, dispatch_id: str) -> ScheduleDispatchRecord | None:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute('SELECT * FROM schedule_dispatches WHERE dispatch_id = ?', (dispatch_id,))
            row = await cursor.fetchone()
            return ScheduleDispatchRecord.model_validate(dict(row)) if row is not None else None
        finally:
            await connection.close()

    async def set_dispatch_state(self, run_id: str, state: DispatchState, error: str | None = None) -> None:
        await self.initialize()
        connection = await self._connect()
        try:
            await connection.execute(
                'UPDATE schedule_dispatches SET state = ?, error = ?, updated_at = ? WHERE run_id = ?',
                (state, error, utc_iso(utc_now_datetime()), run_id),
            )
            await connection.commit()
        except aiosqlite.Error as store_error:
            raise ScheduleStoreError('Could not update scheduled run state') from store_error
        finally:
            await connection.close()

    async def pending_dispatches(
        self,
        schedule_id: str,
        *,
        reserved_only: bool = False,
    ) -> list[ScheduleDispatchRecord]:
        await self.initialize()
        connection = await self._connect()
        try:
            states = "state = 'reserved'" if reserved_only else "state IN ('reserved', 'queued', 'running', 'cancelling')"
            cursor = await connection.execute(
                f'SELECT * FROM schedule_dispatches WHERE schedule_id = ? AND {states} ORDER BY scheduled_for, target',
                (schedule_id,),
            )
            return [ScheduleDispatchRecord.model_validate(dict(row)) for row in await cursor.fetchall()]
        finally:
            await connection.close()

    async def list_dispatches(
        self,
        schedule_id: str,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[ScheduleDispatchRecord]:
        await self.initialize()
        connection = await self._connect()
        try:
            cursor = await connection.execute(
                'SELECT * FROM schedule_dispatches WHERE schedule_id = ? ORDER BY scheduled_for DESC, target LIMIT ? OFFSET ?',
                (schedule_id, limit, offset),
            )
            return [ScheduleDispatchRecord.model_validate(dict(row)) for row in await cursor.fetchall()]
        finally:
            await connection.close()

    async def release_claims(self, owner_id: str) -> None:
        await self.initialize()
        connection = await self._connect()
        try:
            await connection.execute(
                'UPDATE schedules SET claim_owner = NULL, claim_until = NULL WHERE claim_owner = ?',
                (owner_id,),
            )
            await connection.commit()
        finally:
            await connection.close()
