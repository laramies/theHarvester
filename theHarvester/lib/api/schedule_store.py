from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    delete,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL, RowMapping
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from theHarvester.lib.database import sqlite_engine

from .run_artifacts import RunPaths, ensure_private_directory
from .schedule_models import (
    DispatchState,
    ScheduleCreate,
    ScheduleDispatchRecord,
    ScheduleResponse,
    ScheduleTiming,
    parse_utc,
    utc_iso,
    utc_now_datetime,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class ScheduleStoreError(RuntimeError):
    """Persistent schedule state could not be read or updated."""


def configured_schedule_database(run_database: str | Path | None = None) -> Path:
    configured = os.getenv('THEHARVESTER_SCHEDULE_DB')
    if configured:
        return Path(configured).expanduser()
    run_database_path = RunPaths.configured(run_database).database
    return run_database_path.with_name(f'{run_database_path.stem}.schedules.sqlite')


_SCHEDULE_METADATA = MetaData()
_SCHEDULES = Table(
    'schedules',
    _SCHEDULE_METADATA,
    Column('schedule_id', Text, primary_key=True),
    Column('name', Text, nullable=False),
    Column('targets_json', Text, nullable=False),
    Column('run_json', Text, nullable=False),
    Column('timing_json', Text, nullable=False),
    Column('enabled', Integer, nullable=False),
    Column('overlap_policy', Text, nullable=False),
    Column('created_at', Text, nullable=False),
    Column('updated_at', Text, nullable=False),
    Column('next_run_at', Text),
    Column('last_run_at', Text),
    Column('last_error', Text),
    Column('claim_owner', Text),
    Column('claim_until', Text),
    CheckConstraint('enabled IN (0, 1)'),
    CheckConstraint("overlap_policy IN ('skip', 'queue')"),
)
Index('schedules_due_idx', _SCHEDULES.c.enabled, _SCHEDULES.c.next_run_at, _SCHEDULES.c.claim_until)

_SCHEDULE_DISPATCHES = Table(
    'schedule_dispatches',
    _SCHEDULE_METADATA,
    Column('dispatch_id', Text, primary_key=True),
    Column('schedule_id', Text, ForeignKey('schedules.schedule_id', ondelete='CASCADE'), nullable=False),
    Column('scheduled_for', Text, nullable=False),
    Column('target', Text, nullable=False),
    Column('run_id', Text, nullable=False, unique=True),
    Column('state', Text, nullable=False),
    Column('error', Text),
    Column('created_at', Text, nullable=False),
    Column('updated_at', Text, nullable=False),
    CheckConstraint("state IN ('reserved', 'queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled')"),
    UniqueConstraint('schedule_id', 'scheduled_for', 'target'),
)
Index(
    'schedule_dispatches_schedule_idx',
    _SCHEDULE_DISPATCHES.c.schedule_id,
    _SCHEDULE_DISPATCHES.c.scheduled_for.desc(),
)
Index(
    'schedule_dispatches_pending_idx',
    _SCHEDULE_DISPATCHES.c.schedule_id,
    _SCHEDULE_DISPATCHES.c.state,
)


class _ScheduleDatabase:
    """Own the SQLAlchemy engine and schema for one private schedule database."""

    def __init__(self, database: Path) -> None:
        self.database = database
        self.engine = sqlite_engine(database)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self._initialize_lock = asyncio.Lock()
        self._initialized = False

    def reject_symlink(self) -> None:
        if self.database.is_symlink():
            raise ScheduleStoreError(f'Refusing symlinked schedule database: {self.database}')

    async def initialize(self) -> None:
        if self._initialized and self.database.exists():
            return
        async with self._initialize_lock:
            if self._initialized and self.database.exists():
                return
            ensure_private_directory(self.database.parent)
            self.reject_symlink()
            if self._initialized:
                await self.engine.dispose()
                self.engine = sqlite_engine(self.database)
                self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
            initialization_engine = create_async_engine(
                URL.create('sqlite+aiosqlite', database=str(self.database)),
                connect_args={'isolation_level': None, 'timeout': 30},
            )
            try:
                async with initialization_engine.connect() as connection:
                    await connection.exec_driver_sql('BEGIN IMMEDIATE')
                    try:
                        await connection.run_sync(_SCHEDULE_METADATA.create_all)
                        await connection.commit()
                    except BaseException:
                        await connection.rollback()
                        raise
                    journal_mode = await connection.exec_driver_sql('PRAGMA journal_mode = WAL')
                    if str(journal_mode.scalar_one()).casefold() != 'wal':
                        raise ScheduleStoreError('Could not enable WAL mode for schedule database')
            except SQLAlchemyError as error:
                raise ScheduleStoreError('Could not initialize schedule database') from error
            finally:
                await initialization_engine.dispose()
            try:
                async with self.engine.connect() as connection:
                    foreign_keys = await connection.exec_driver_sql('PRAGMA foreign_keys')
                    if foreign_keys.scalar_one() != 1:
                        raise ScheduleStoreError('SQLite foreign-key enforcement is not enabled')
            except SQLAlchemyError as error:
                raise ScheduleStoreError('Could not initialize schedule database') from error
            self.database.chmod(0o600)
            self._initialized = True

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        self.reject_symlink()
        async with self.sessions() as session:
            yield session

    async def dispose(self) -> None:
        self._initialized = False
        await self.engine.dispose()


_SCHEDULE_DATABASES: dict[str, _ScheduleDatabase] = {}


def _database_for(database: Path) -> _ScheduleDatabase:
    key = str(database)
    if key not in _SCHEDULE_DATABASES:
        _SCHEDULE_DATABASES[key] = _ScheduleDatabase(database)
    return _SCHEDULE_DATABASES[key]


def _row_count(result: Any) -> int:
    return int(result.rowcount)


class ScheduleStore:
    """Persist scheduler control-plane state separately from portable run evidence."""

    def __init__(self, database: str | Path | None = None) -> None:
        self.database = configured_schedule_database(database).expanduser().absolute()
        self._database = _database_for(self.database)

    async def initialize(self) -> None:
        self._database = _database_for(self.database)
        await self._database.initialize()

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        await self._database.initialize()
        async with self._database.session() as session:
            yield session

    @staticmethod
    def _response(row: RowMapping) -> ScheduleResponse:
        timing = ScheduleTiming.model_validate_json(row['timing_json'])
        next_run_at = row['next_run_at']
        return ScheduleResponse.model_validate(
            {
                'schedule_id': row['schedule_id'],
                'name': row['name'],
                'targets': json.loads(row['targets_json']),
                'run': json.loads(row['run_json']),
                'timing': timing,
                'enabled': bool(row['enabled']),
                'overlap_policy': row['overlap_policy'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'next_run_at': next_run_at,
                'upcoming_occurrences': [
                    utc_iso(occurrence)
                    for occurrence in timing.upcoming_occurrences(parse_utc(next_run_at) if next_run_at else None)
                ],
                'last_run_at': row['last_run_at'],
                'last_error': row['last_error'],
            }
        )

    @staticmethod
    def _dispatch(row: RowMapping) -> ScheduleDispatchRecord:
        return ScheduleDispatchRecord.model_validate(dict(row))

    async def create(self, request: ScheduleCreate) -> ScheduleResponse:
        now_text = utc_iso(utc_now_datetime())
        schedule_id = str(uuid4())
        next_run_at = utc_iso(request.timing.first_due_at()) if request.enabled else None
        try:
            async with self._session() as session:
                await session.execute(
                    _SCHEDULES.insert().values(
                        schedule_id=schedule_id,
                        name=request.name,
                        targets_json=json.dumps(request.targets, separators=(',', ':')),
                        run_json=request.run.model_dump_json(),
                        timing_json=request.timing.model_dump_json(),
                        enabled=int(request.enabled),
                        overlap_policy=request.overlap_policy,
                        created_at=now_text,
                        updated_at=now_text,
                        next_run_at=next_run_at,
                    )
                )
                await session.commit()
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not create schedule') from error
        created = await self.get(schedule_id)
        assert created is not None
        return created

    async def list_schedules(self, *, limit: int = 100, offset: int = 0) -> list[ScheduleResponse]:
        try:
            async with self._session() as session:
                rows = (
                    await session.execute(select(_SCHEDULES).order_by(_SCHEDULES.c.created_at.desc()).limit(limit).offset(offset))
                ).mappings()
                return [self._response(row) for row in rows]
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not list schedules') from error

    async def get(self, schedule_id: str) -> ScheduleResponse | None:
        try:
            async with self._session() as session:
                row = (
                    (await session.execute(select(_SCHEDULES).where(_SCHEDULES.c.schedule_id == schedule_id)))
                    .mappings()
                    .one_or_none()
                )
                return self._response(row) if row is not None else None
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not read schedule') from error

    async def replace(self, schedule_id: str, request: ScheduleCreate) -> ScheduleResponse | None:
        existing = await self.get(schedule_id)
        if existing is None:
            return None
        now = utc_now_datetime()
        now_text = utc_iso(now)
        next_value: datetime | None
        if request.enabled and request.timing.frequency == 'once' and existing.last_run_at is None:
            next_value = request.timing.first_due_at()
        else:
            next_value = request.timing.next_after(now - timedelta(microseconds=1)) if request.enabled else None
        try:
            async with self._session() as session:
                result = await session.execute(
                    update(_SCHEDULES)
                    .where(_SCHEDULES.c.schedule_id == schedule_id)
                    .values(
                        name=request.name,
                        targets_json=json.dumps(request.targets, separators=(',', ':')),
                        run_json=request.run.model_dump_json(),
                        timing_json=request.timing.model_dump_json(),
                        enabled=int(request.enabled),
                        overlap_policy=request.overlap_policy,
                        updated_at=now_text,
                        next_run_at=utc_iso(next_value) if next_value is not None else None,
                        claim_owner=None,
                        claim_until=None,
                    )
                )
                await session.commit()
                if _row_count(result) == 0:
                    return None
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not update schedule') from error
        return await self.get(schedule_id)

    async def set_enabled(self, schedule_id: str, enabled: bool) -> ScheduleResponse | None:
        existing = await self.get(schedule_id)
        if existing is None:
            return None
        now = utc_now_datetime()
        if enabled:
            first_due_at = existing.timing.first_due_at()
            if (
                existing.timing.frequency == 'once'
                and existing.last_run_at is not None
                and first_due_at <= parse_utc(existing.last_run_at)
            ):
                next_run_at = None
            elif existing.last_run_at is None:
                next_run_at = utc_iso(first_due_at)
            else:
                next_value = existing.timing.next_after(now - timedelta(microseconds=1))
                next_run_at = utc_iso(next_value) if next_value is not None else None
        else:
            next_run_at = None
        try:
            async with self._session() as session:
                result = await session.execute(
                    update(_SCHEDULES)
                    .where(_SCHEDULES.c.schedule_id == schedule_id)
                    .values(
                        enabled=int(enabled),
                        updated_at=utc_iso(now),
                        next_run_at=next_run_at,
                        claim_owner=None,
                        claim_until=None,
                    )
                )
                await session.commit()
                if _row_count(result) == 0:
                    return None
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not change schedule state') from error
        return await self.get(schedule_id)

    async def delete(self, schedule_id: str) -> bool:
        try:
            async with self._session() as session:
                result = await session.execute(delete(_SCHEDULES).where(_SCHEDULES.c.schedule_id == schedule_id))
                await session.commit()
                return _row_count(result) > 0
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not delete schedule') from error

    async def next_due_at(self) -> datetime | None:
        try:
            async with self._session() as session:
                value = await session.scalar(
                    select(func.min(_SCHEDULES.c.next_run_at)).where(
                        _SCHEDULES.c.enabled == 1,
                        _SCHEDULES.c.next_run_at.is_not(None),
                    )
                )
                return parse_utc(str(value)) if value else None
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not read the next due schedule') from error

    async def claim_due(
        self,
        owner_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 60,
        limit: int = 10,
    ) -> list[ScheduleResponse]:
        current = (now or utc_now_datetime()).astimezone(UTC)
        now_text = utc_iso(current)
        available = (
            (_SCHEDULES.c.enabled == 1)
            & _SCHEDULES.c.next_run_at.is_not(None)
            & (_SCHEDULES.c.next_run_at <= now_text)
            & or_(_SCHEDULES.c.claim_until.is_(None), _SCHEDULES.c.claim_until < now_text)
        )
        candidates = (
            select(_SCHEDULES.c.schedule_id)
            .where(available)
            .order_by(_SCHEDULES.c.next_run_at, _SCHEDULES.c.schedule_id)
            .limit(limit)
        )
        try:
            async with self._session() as session:
                rows = list(
                    (
                        await session.execute(
                            update(_SCHEDULES)
                            .where(_SCHEDULES.c.schedule_id.in_(candidates), available)
                            .values(
                                claim_owner=owner_id,
                                claim_until=utc_iso(current + timedelta(seconds=lease_seconds)),
                            )
                            .returning(_SCHEDULES)
                        )
                    )
                    .mappings()
                    .all()
                )
                await session.commit()
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not claim due schedules') from error
        rows.sort(key=lambda row: (str(row['next_run_at']), str(row['schedule_id'])))
        return [self._response(row) for row in rows]

    async def renew_claim(self, schedule_id: str, owner_id: str, *, lease_seconds: int = 60) -> bool:
        try:
            async with self._session() as session:
                result = await session.execute(
                    update(_SCHEDULES)
                    .where(_SCHEDULES.c.schedule_id == schedule_id, _SCHEDULES.c.claim_owner == owner_id)
                    .values(claim_until=utc_iso(utc_now_datetime() + timedelta(seconds=lease_seconds)))
                )
                await session.commit()
                return _row_count(result) > 0
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not renew schedule claim') from error

    async def complete_claim(
        self,
        schedule_id: str,
        owner_id: str,
        *,
        scheduled_for: datetime,
        next_run_at: datetime | None,
        error: str | None = None,
    ) -> bool:
        try:
            async with self._session() as session:
                result = await session.execute(
                    update(_SCHEDULES)
                    .where(_SCHEDULES.c.schedule_id == schedule_id, _SCHEDULES.c.claim_owner == owner_id)
                    .values(
                        last_run_at=utc_iso(scheduled_for),
                        next_run_at=utc_iso(next_run_at) if next_run_at is not None else None,
                        last_error=error,
                        updated_at=utc_iso(utc_now_datetime()),
                        claim_owner=None,
                        claim_until=None,
                    )
                )
                await session.commit()
                return _row_count(result) > 0
        except SQLAlchemyError as store_error:
            raise ScheduleStoreError('Could not complete schedule claim') from store_error

    async def defer_claim(self, schedule_id: str, owner_id: str, *, seconds: int, error: str) -> bool:
        now = utc_now_datetime()
        try:
            async with self._session() as session:
                result = await session.execute(
                    update(_SCHEDULES)
                    .where(_SCHEDULES.c.schedule_id == schedule_id, _SCHEDULES.c.claim_owner == owner_id)
                    .values(
                        last_error=error,
                        updated_at=utc_iso(now),
                        claim_owner=None,
                        claim_until=utc_iso(now + timedelta(seconds=seconds)),
                    )
                )
                await session.commit()
                return _row_count(result) > 0
        except SQLAlchemyError as store_error:
            raise ScheduleStoreError('Could not defer schedule claim') from store_error

    async def reserve_dispatch(
        self,
        schedule_id: str,
        scheduled_for: datetime,
        target: str,
        run_id: str,
    ) -> ScheduleDispatchRecord | None:
        dispatches = await self.reserve_dispatches(schedule_id, scheduled_for, {target: run_id})
        return dispatches[0] if dispatches else None

    async def reserve_dispatches(
        self,
        schedule_id: str,
        scheduled_for: datetime,
        target_run_ids: dict[str, str],
    ) -> list[ScheduleDispatchRecord]:
        """Reserve every target together so retries can recover the whole occurrence."""
        if not target_run_ids:
            return []
        now_text = utc_iso(utc_now_datetime())
        scheduled_for_text = utc_iso(scheduled_for)
        reservations = [
            {
                'dispatch_id': str(uuid4()),
                'schedule_id': schedule_id,
                'scheduled_for': scheduled_for_text,
                'target': target,
                'run_id': run_id,
                'state': 'reserved',
                'created_at': now_text,
                'updated_at': now_text,
            }
            for target, run_id in target_run_ids.items()
        ]
        try:
            async with self._session() as session:
                await session.execute(sqlite_insert(_SCHEDULE_DISPATCHES).on_conflict_do_nothing(), reservations)
                rows = (
                    (
                        await session.execute(
                            select(_SCHEDULE_DISPATCHES).where(
                                _SCHEDULE_DISPATCHES.c.schedule_id == schedule_id,
                                _SCHEDULE_DISPATCHES.c.scheduled_for == scheduled_for_text,
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
                records = {str(row['target']): self._dispatch(row) for row in rows}
                if not target_run_ids.keys() <= records.keys():
                    await session.rollback()
                    raise ScheduleStoreError('Could not reserve every scheduled run')
                await session.commit()
                return [records[target] for target in target_run_ids]
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not reserve scheduled runs') from error

    async def get_dispatch(self, dispatch_id: str) -> ScheduleDispatchRecord | None:
        try:
            async with self._session() as session:
                row = (
                    (await session.execute(select(_SCHEDULE_DISPATCHES).where(_SCHEDULE_DISPATCHES.c.dispatch_id == dispatch_id)))
                    .mappings()
                    .one_or_none()
                )
                return self._dispatch(row) if row is not None else None
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not read scheduled run') from error

    async def set_dispatch_state(self, run_id: str, state: DispatchState, error: str | None = None) -> None:
        try:
            async with self._session() as session:
                await session.execute(
                    update(_SCHEDULE_DISPATCHES)
                    .where(_SCHEDULE_DISPATCHES.c.run_id == run_id)
                    .values(state=state, error=error, updated_at=utc_iso(utc_now_datetime()))
                )
                await session.commit()
        except SQLAlchemyError as store_error:
            raise ScheduleStoreError('Could not update scheduled run state') from store_error

    async def pending_dispatches(
        self,
        schedule_id: str,
        *,
        reserved_only: bool = False,
    ) -> list[ScheduleDispatchRecord]:
        states = ('reserved',) if reserved_only else ('reserved', 'queued', 'running', 'cancelling')
        try:
            async with self._session() as session:
                rows = (
                    await session.execute(
                        select(_SCHEDULE_DISPATCHES)
                        .where(
                            _SCHEDULE_DISPATCHES.c.schedule_id == schedule_id,
                            _SCHEDULE_DISPATCHES.c.state.in_(states),
                        )
                        .order_by(_SCHEDULE_DISPATCHES.c.scheduled_for, _SCHEDULE_DISPATCHES.c.target)
                    )
                ).mappings()
                return [self._dispatch(row) for row in rows]
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not read pending scheduled runs') from error

    async def list_dispatches(
        self,
        schedule_id: str,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[ScheduleDispatchRecord]:
        try:
            async with self._session() as session:
                rows = (
                    await session.execute(
                        select(_SCHEDULE_DISPATCHES)
                        .where(_SCHEDULE_DISPATCHES.c.schedule_id == schedule_id)
                        .order_by(_SCHEDULE_DISPATCHES.c.scheduled_for.desc(), _SCHEDULE_DISPATCHES.c.target)
                        .limit(limit)
                        .offset(offset)
                    )
                ).mappings()
                return [self._dispatch(row) for row in rows]
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not list scheduled runs') from error

    async def release_claims(self, owner_id: str) -> None:
        try:
            async with self._session() as session:
                await session.execute(
                    update(_SCHEDULES).where(_SCHEDULES.c.claim_owner == owner_id).values(claim_owner=None, claim_until=None)
                )
                await session.commit()
        except SQLAlchemyError as error:
            raise ScheduleStoreError('Could not release schedule claims') from error


async def dispose_schedule_databases() -> None:
    """Close every shared SQLAlchemy engine used by schedule stores."""
    databases = tuple(_SCHEDULE_DATABASES.values())
    _SCHEDULE_DATABASES.clear()
    await asyncio.gather(*(database.dispose() for database in databases))
