import asyncio
import datetime
import json
import logging
import sqlite3
from collections import Counter
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Date,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Text,
    UniqueConstraint,
    delete,
    event,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from theHarvester.lib.active_evidence import (
    ActionExecution,
    ActionObservation,
    ActionYield,
    ActiveEvidence,
    ArtifactReference,
)
from theHarvester.lib.asn_attribution import (
    AsnAttributionObservation,
    canonical_asn_attributions,
)
from theHarvester.lib.completed_result import (
    CompletedResult,
    ExecutionStatus,
    ResultKind,
    ResultObservation,
    SourceExecution,
    SourceYield,
    parse_virtual_host_details,
    virtual_host_details,
)
from theHarvester.lib.dns_consensus import Addressability
from theHarvester.lib.hostname_tracking import TrackingRunEvidence, TrackingSourceOutcome
from theHarvester.lib.network_evidence import (
    NetworkObservation,
    network_observation_details,
    network_observation_sort_key,
    parse_network_observation_json,
)
from theHarvester.lib.shodan_evidence import ShodanHostObservation, canonical_shodan_hosts
from theHarvester.lib.takeover_evidence import (
    TakeoverCandidateOutcome,
    canonical_takeover_outcomes,
    parse_takeover_details,
)
from theHarvester.lib.virtual_host import VirtualHostObservation

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

    from theHarvester.lib.asn_attribution import ProducerKind, SubjectKind
    from theHarvester.lib.evidence_types import EvidenceStatus

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 8
_DEFAULT_DATABASE = Path('~/.local/share/theHarvester/stash.sqlite').expanduser()
_PORTABLE_DATABASE_DROP_STATEMENTS = (
    'DROP TABLE IF EXISTS legacy_observations',
    'DROP TABLE IF EXISTS run_records',
    'DROP TABLE IF EXISTS run_worker_leases',
)

_LEGACY_RESULT_KIND_RENAMES = {
    'api-endpoint': 'url',
    'api_endpoint': 'url',
    'interesting-url': 'url',
    'interestingurls': 'url',
    'ip-address': 'ip',
    'linkedin-link': 'url',
    'linkedinlinks': 'url',
    'vhost': 'hostname',
}


class ResultStoreError(RuntimeError):
    """The result store could not complete an operation."""


class DuplicateRunError(ResultStoreError):
    """A persisted enumeration run already uses the requested run ID."""


def _sqlite_has_wal_reset_fix(version: tuple[int, int, int]) -> bool:
    return (
        version >= (3, 51, 3)
        or (version[:2] == (3, 50) and version >= (3, 50, 7))
        or (version[:2] == (3, 44) and version >= (3, 44, 6))
    )


class _Base(DeclarativeBase):
    pass


class _LegacyObservationRow(_Base):
    """A runless source observation, including incomplete rows from older databases."""

    __tablename__ = 'legacy_observations'

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str | None] = mapped_column(Text, index=True)
    resource: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str | None] = mapped_column(Text, index=True)
    discovered_on: Mapped[date | None] = mapped_column(Date, index=True)
    source: Mapped[str | None] = mapped_column(Text)


class _RunRow(_Base):
    """One enumeration run and the time window in which it ran."""

    __tablename__ = 'runs'

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    target: Mapped[str] = mapped_column(Text)
    started_at: Mapped[str] = mapped_column(Text)
    completed_at: Mapped[str] = mapped_column(Text)
    evidence_status: Mapped[str | None] = mapped_column(Text)


class _ResultRow(_Base):
    """One deduplicated result from a run, kept in output order."""

    __tablename__ = 'results'
    __table_args__ = (UniqueConstraint('run_id', 'kind', 'value'),)

    run_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey('runs.run_id', ondelete='CASCADE'),
        primary_key=True,
    )
    position: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    details_json: Mapped[str | None] = mapped_column(Text)


class _ExecutionRow(_Base):
    """One source or action that ran as part of an enumeration."""

    __tablename__ = 'executions'
    __table_args__ = (UniqueConstraint('run_id', 'producer_kind', 'name'),)

    run_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey('runs.run_id', ondelete='CASCADE'),
        primary_key=True,
    )
    position: Mapped[int] = mapped_column(primary_key=True)
    producer_kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    duration_ms: Mapped[float] = mapped_column(Float)
    result_count: Mapped[int]
    error_type: Mapped[str | None] = mapped_column(Text)
    stop_reason: Mapped[str | None] = mapped_column(Text)


class _ResultOriginRow(_Base):
    """Link one persisted result to the execution that produced it."""

    __tablename__ = 'result_origins'
    __table_args__ = (
        ForeignKeyConstraint(
            ('run_id', 'result_position'),
            ('results.run_id', 'results.position'),
            ondelete='CASCADE',
        ),
        ForeignKeyConstraint(
            ('run_id', 'execution_position'),
            ('executions.run_id', 'executions.position'),
            ondelete='CASCADE',
        ),
    )

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    result_position: Mapped[int] = mapped_column(primary_key=True)
    execution_position: Mapped[int] = mapped_column(primary_key=True)


class _AsnAttributionRow(_Base):
    """One sourced organization label connecting an ASN to a hostname or IP result."""

    __tablename__ = 'asn_attributions'
    __table_args__ = (
        ForeignKeyConstraint(
            ('run_id', 'asn_result_position'),
            ('results.run_id', 'results.position'),
            ondelete='CASCADE',
        ),
        ForeignKeyConstraint(
            ('run_id', 'subject_result_position'),
            ('results.run_id', 'results.position'),
            ondelete='CASCADE',
        ),
        ForeignKeyConstraint(
            ('run_id', 'execution_position'),
            ('executions.run_id', 'executions.position'),
            ondelete='CASCADE',
        ),
    )

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(primary_key=True)
    asn_result_position: Mapped[int]
    subject_result_position: Mapped[int]
    execution_position: Mapped[int]
    organization_label: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[str] = mapped_column(Text)


class _ArtifactRow(_Base):
    """Metadata for a file created by an action and attached to one result."""

    __tablename__ = 'artifacts'
    __table_args__ = (
        ForeignKeyConstraint(
            ('run_id', 'result_position'),
            ('results.run_id', 'results.position'),
            ondelete='CASCADE',
        ),
        ForeignKeyConstraint(
            ('run_id', 'execution_position'),
            ('executions.run_id', 'executions.position'),
            ondelete='CASCADE',
        ),
        CheckConstraint('size_bytes >= 0'),
        CheckConstraint("length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'"),
    )

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(primary_key=True)
    result_position: Mapped[int]
    execution_position: Mapped[int]
    kind: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    media_type: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int]
    sha256: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)


class _RunRecordRow(_Base):
    """Lifecycle state for one API-submitted or imported run."""

    __tablename__ = 'run_records'

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    target: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)
    started_at: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[str | None] = mapped_column(Text)
    request_json: Mapped[str] = mapped_column(Text)
    evidence_run_id: Mapped[str | None] = mapped_column(Text, ForeignKey('runs.run_id', ondelete='SET NULL'))
    evidence_status: Mapped[str | None] = mapped_column(Text)
    cancellation_requested_at: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    log: Mapped[str] = mapped_column(Text, default='')


class _WorkerLeaseRow(_Base):
    """The current owner of the single local API execution worker."""

    __tablename__ = 'run_worker_leases'

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    owner_id: Mapped[str] = mapped_column(Text)
    heartbeat_at: Mapped[str] = mapped_column(Text)


def _configure_sqlite_connection(dbapi_connection: Any, _connection_record: Any) -> None:
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.close()


def _begin_sqlite_transaction(connection: Any) -> None:
    connection.exec_driver_sql('BEGIN')


def sqlite_engine(database: str | Path) -> AsyncEngine:
    """Create an async SQLite engine with the project's transaction settings."""
    engine = create_async_engine(
        URL.create('sqlite+aiosqlite', database=str(Path(database).expanduser().resolve())),
        connect_args={'autocommit': sqlite3.LEGACY_TRANSACTION_CONTROL, 'timeout': 30},
    )
    event.listen(engine.sync_engine, 'connect', _configure_sqlite_connection)
    event.listen(engine.sync_engine, 'begin', _begin_sqlite_transaction)
    return engine


async def _canonicalize_result_kinds(connection: AsyncConnection) -> None:
    """Merge result-kind aliases without losing provenance or artifact references."""
    aliases = ', '.join(f"'{kind}'" for kind in sorted(_LEGACY_RESULT_KIND_RENAMES))
    run_rows = await connection.exec_driver_sql(f'SELECT DISTINCT run_id FROM results WHERE kind IN ({aliases})')
    for (run_id,) in run_rows:
        result_rows = list(
            await connection.exec_driver_sql(
                'SELECT position, kind, value FROM results WHERE run_id = ? ORDER BY position',
                (run_id,),
            )
        )
        origin_rows = list(
            await connection.exec_driver_sql(
                'SELECT result_position, execution_position FROM result_origins WHERE run_id = ?',
                (run_id,),
            )
        )
        artifact_rows = list(
            await connection.exec_driver_sql(
                'SELECT position, result_position, execution_position, kind, path, media_type, '
                'size_bytes, sha256, created_at FROM artifacts WHERE run_id = ? ORDER BY position',
                (run_id,),
            )
        )

        canonical_results = sorted(
            {(_LEGACY_RESULT_KIND_RENAMES.get(kind, kind), value) for _position, kind, value in result_rows}
        )
        new_positions = {result: position for position, result in enumerate(canonical_results)}
        old_positions = {
            position: new_positions[(_LEGACY_RESULT_KIND_RENAMES.get(kind, kind), value)] for position, kind, value in result_rows
        }
        canonical_origins = sorted(
            {(old_positions[result_position], execution_position) for result_position, execution_position in origin_rows}
        )

        await connection.exec_driver_sql('DELETE FROM artifacts WHERE run_id = ?', (run_id,))
        await connection.exec_driver_sql('DELETE FROM result_origins WHERE run_id = ?', (run_id,))
        await connection.exec_driver_sql('DELETE FROM results WHERE run_id = ?', (run_id,))
        if canonical_results:
            await connection.exec_driver_sql(
                'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
                [(run_id, position, kind, value) for position, (kind, value) in enumerate(canonical_results)],
            )
        if canonical_origins:
            await connection.exec_driver_sql(
                'INSERT INTO result_origins (run_id, result_position, execution_position) VALUES (?, ?, ?)',
                [(run_id, result_position, execution_position) for result_position, execution_position in canonical_origins],
            )
        if artifact_rows:
            await connection.exec_driver_sql(
                'INSERT INTO artifacts '
                '(run_id, position, result_position, execution_position, kind, path, media_type, size_bytes, sha256, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (
                        run_id,
                        position,
                        old_positions[result_position],
                        execution_position,
                        kind,
                        path,
                        media_type,
                        size_bytes,
                        sha256,
                        created_at,
                    )
                    for (
                        position,
                        result_position,
                        execution_position,
                        kind,
                        path,
                        media_type,
                        size_bytes,
                        sha256,
                        created_at,
                    ) in artifact_rows
                ],
            )
        await connection.exec_driver_sql(
            'UPDATE executions SET result_count = ('
            'SELECT COUNT(*) FROM result_origins '
            'WHERE result_origins.run_id = executions.run_id '
            'AND result_origins.execution_position = executions.position'
            ') WHERE run_id = ?',
            (run_id,),
        )

    for alias, canonical in _LEGACY_RESULT_KIND_RENAMES.items():
        await connection.exec_driver_sql(
            'UPDATE legacy_observations SET kind = ? WHERE kind = ?',
            (canonical, alias),
        )


class _SQLiteDatabase:
    def __init__(self, database: str | Path) -> None:
        self.database = str(Path(database).expanduser().resolve())
        self.engine = sqlite_engine(database)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self._initialize_lock = asyncio.Lock()
        self._initialized = False

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessions() as session:
            yield session

    async def initialize(self) -> None:
        if self._initialized:
            return
        async with self._initialize_lock:
            if self._initialized:
                return
            initialization_engine = create_async_engine(
                URL.create('sqlite+aiosqlite', database=self.database),
                connect_args={'isolation_level': None, 'timeout': 30},
            )
            try:
                async with initialization_engine.connect() as connection:
                    await connection.exec_driver_sql('BEGIN IMMEDIATE')
                    try:
                        version_result = await connection.exec_driver_sql('PRAGMA user_version')
                        schema_version = version_result.scalar_one()
                        if schema_version > SCHEMA_VERSION:
                            raise RuntimeError(
                                f'Database schema version {schema_version} is newer than supported version {SCHEMA_VERSION}'
                            )
                        has_legacy_results = False
                        if schema_version == 0:
                            table_rows = await connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type = 'table'")
                            tables = {row[0] for row in table_rows}
                            has_legacy_results = 'results' in tables and 'runs' not in tables
                            if has_legacy_results:
                                await connection.exec_driver_sql('ALTER TABLE results RENAME TO legacy_results')
                            if 'completed_results' in tables:
                                await connection.exec_driver_sql('ALTER TABLE completed_results RENAME TO runs')
                            if 'completed_result_items' in tables:
                                await connection.exec_driver_sql('ALTER TABLE completed_result_items RENAME TO results')
                        else:
                            table_rows = await connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type = 'table'")
                            tables = {row[0] for row in table_rows}
                        if 'discovery_observations' in tables and 'legacy_observations' not in tables:
                            await connection.exec_driver_sql('ALTER TABLE discovery_observations RENAME TO legacy_observations')
                        await connection.run_sync(_Base.metadata.create_all)
                        run_column_rows = await connection.exec_driver_sql('PRAGMA table_info(runs)')
                        if 'evidence_status' not in {row[1] for row in run_column_rows}:
                            await connection.exec_driver_sql('ALTER TABLE runs ADD COLUMN evidence_status TEXT')
                        result_column_rows = await connection.exec_driver_sql('PRAGMA table_info(results)')
                        if 'details_json' not in {row[1] for row in result_column_rows}:
                            await connection.exec_driver_sql('ALTER TABLE results ADD COLUMN details_json TEXT')
                        if has_legacy_results:
                            await connection.exec_driver_sql(
                                'INSERT INTO legacy_observations (domain, resource, kind, discovered_on, source) '
                                'SELECT domain, resource, CASE type '
                                "WHEN 'host' THEN 'hostname' "
                                "WHEN 'people' THEN 'person' "
                                "WHEN 'asns' THEN 'asn' "
                                'ELSE type END, find_date, source FROM legacy_results'
                            )
                            await connection.exec_driver_sql('DROP TABLE legacy_results')
                        if schema_version < SCHEMA_VERSION:
                            await _canonicalize_result_kinds(connection)
                        await connection.exec_driver_sql(f'PRAGMA user_version = {SCHEMA_VERSION}')
                        await connection.commit()
                    except BaseException:
                        await connection.rollback()
                        raise
                    journal_mode = 'WAL' if _sqlite_has_wal_reset_fix(sqlite3.sqlite_version_info) else 'DELETE'
                    journal_result = await connection.exec_driver_sql(f'PRAGMA journal_mode = {journal_mode}')
                    actual_journal_mode = journal_result.scalar_one()
                    if actual_journal_mode.casefold() != journal_mode.casefold():
                        raise RuntimeError(f'Could not set SQLite journal mode to {journal_mode}: got {actual_journal_mode}')
            finally:
                await initialization_engine.dispose()
            async with self.engine.connect() as runtime_connection:
                foreign_keys = await runtime_connection.exec_driver_sql('PRAGMA foreign_keys')
                if foreign_keys.scalar_one() != 1:
                    raise RuntimeError('SQLite foreign-key enforcement is not enabled')
            self._initialized = True

    async def dispose(self) -> None:
        await self.engine.dispose()


_databases: dict[str, _SQLiteDatabase] = {}


def _database_for(database: str | Path) -> _SQLiteDatabase:
    path = str(Path(database).expanduser().resolve())
    if path not in _databases:
        _databases[path] = _SQLiteDatabase(path)
    return _databases[path]


def _row_count(result: Any) -> int:
    return int(result.rowcount)


def _finalize_portable_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        connection.execute('PRAGMA journal_mode = DELETE')
        for statement in _PORTABLE_DATABASE_DROP_STATEMENTS:
            connection.execute(statement)
        connection.commit()
        connection.execute('VACUUM')


class RunLifecycleStore:
    """Persist API run state in the same SQLite database as terminal evidence."""

    def __init__(self, database: str | Path | None = None) -> None:
        self.database = str(Path(database or _DEFAULT_DATABASE).expanduser().resolve())

    async def initialize(self) -> None:
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        await _database_for(self.database).initialize()

    async def create(
        self,
        *,
        run_id: str,
        target: str,
        status: str,
        origin: str,
        created_at: str,
        request_json: str,
        started_at: str | None = None,
        completed_at: str | None = None,
        evidence_run_id: str | None = None,
        evidence_status: str | None = None,
    ) -> None:
        async with self._session() as session:
            session.add(
                _RunRecordRow(
                    run_id=run_id,
                    target=target,
                    status=status,
                    origin=origin,
                    created_at=created_at,
                    started_at=started_at,
                    completed_at=completed_at,
                    request_json=request_json,
                    evidence_run_id=evidence_run_id,
                    evidence_status=evidence_status,
                    cancellation_requested_at=None,
                    error=None,
                    log='',
                )
            )
            await session.commit()

    async def list_records(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, object]]:
        async with self._session() as session:
            result_count = (
                select(func.count(_ResultRow.position))
                .where(_ResultRow.run_id == _RunRecordRow.evidence_run_id)
                .correlate(_RunRecordRow)
                .scalar_subquery()
            )
            rows = (
                await session.execute(
                    select(_RunRecordRow, result_count.label('result_count'))
                    .order_by(_RunRecordRow.created_at.desc(), _RunRecordRow.run_id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            ).all()
        return [self._record(row, result_count=count) for row, count in rows]

    async def get(self, run_id: str) -> dict[str, object] | None:
        async with self._session() as session:
            row = await session.get(_RunRecordRow, run_id)
        return self._record(row) if row is not None else None

    async def cancel(self, run_id: str, requested_at: str) -> dict[str, object] | None:
        async with self._session() as session:
            queued = await session.execute(
                update(_RunRecordRow)
                .where(_RunRecordRow.run_id == run_id, _RunRecordRow.status == 'queued')
                .values(status='cancelled', cancellation_requested_at=requested_at, completed_at=requested_at)
            )
            running = None
            if _row_count(queued) != 1:
                running = await session.execute(
                    update(_RunRecordRow)
                    .where(_RunRecordRow.run_id == run_id, _RunRecordRow.status == 'running')
                    .values(status='cancelling', cancellation_requested_at=requested_at)
                )
            await session.commit()
        row = await self.get(run_id)
        if row is None:
            return None
        if (
            _row_count(queued) == 1
            or (running is not None and _row_count(running) == 1)
            or row['status'] in {'cancelling', 'cancelled'}
        ):
            return row
        raise ValueError(row['status'])

    async def claim_next(self, started_at: str) -> dict[str, object] | None:
        async with self._session() as session:
            candidate = (
                select(_RunRecordRow.run_id)
                .where(_RunRecordRow.status == 'queued')
                .order_by(_RunRecordRow.created_at)
                .limit(1)
                .scalar_subquery()
            )
            result = await session.execute(
                update(_RunRecordRow)
                .where(_RunRecordRow.run_id == candidate, _RunRecordRow.status == 'queued')
                .values(status='running', started_at=started_at)
                .returning(_RunRecordRow.run_id)
            )
            run_id = result.scalar_one_or_none()
            if run_id is None:
                await session.rollback()
                return None
            await session.commit()
        return await self.get(run_id)

    async def finish(
        self,
        run_id: str,
        *,
        completed_at: str,
        evidence_run_id: str | None,
        evidence_status: str | None,
        log: str,
    ) -> None:
        async with self._session() as session:
            await session.execute(
                update(_RunRecordRow)
                .where(_RunRecordRow.run_id == run_id, _RunRecordRow.status.in_({'running', 'cancelling'}))
                .values(
                    status=func.iif(_RunRecordRow.status == 'cancelling', 'cancelled', 'completed'),
                    completed_at=completed_at,
                    evidence_run_id=func.coalesce(evidence_run_id, _RunRecordRow.evidence_run_id),
                    evidence_status=func.coalesce(evidence_status, _RunRecordRow.evidence_status),
                    log=log,
                )
            )
            await session.commit()

    async def fail(
        self,
        run_id: str,
        *,
        status: str,
        completed_at: str,
        error: str,
        log: str,
        evidence_run_id: str | None,
        evidence_status: str | None,
    ) -> None:
        async with self._session() as session:
            await session.execute(
                update(_RunRecordRow)
                .where(_RunRecordRow.run_id == run_id)
                .values(
                    status=status,
                    completed_at=completed_at,
                    error=error,
                    log=log,
                    evidence_run_id=func.coalesce(evidence_run_id, _RunRecordRow.evidence_run_id),
                    evidence_status=func.coalesce(evidence_status, _RunRecordRow.evidence_status),
                )
            )
            await session.commit()

    async def running(self) -> list[dict[str, object]]:
        async with self._session() as session:
            rows = (await session.scalars(select(_RunRecordRow).where(_RunRecordRow.status.in_({'running', 'cancelling'})))).all()
        return [self._record(row) for row in rows]

    async def acquire_lease(self, owner_id: str, now: str, timeout_seconds: int) -> bool:
        async with self._session() as session:
            stale_before = (datetime.datetime.fromisoformat(now) - timedelta(seconds=timeout_seconds)).isoformat()
            statement = sqlite_insert(_WorkerLeaseRow).values(name='executor', owner_id=owner_id, heartbeat_at=now)
            statement = statement.on_conflict_do_update(
                index_elements=[_WorkerLeaseRow.name],
                set_={'owner_id': owner_id, 'heartbeat_at': now},
                where=or_(_WorkerLeaseRow.owner_id == owner_id, _WorkerLeaseRow.heartbeat_at < stale_before),
            )
            result = await session.execute(statement)
            await session.commit()
            return _row_count(result) == 1

    async def heartbeat_lease(self, owner_id: str, now: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                update(_WorkerLeaseRow)
                .where(_WorkerLeaseRow.name == 'executor', _WorkerLeaseRow.owner_id == owner_id)
                .values(heartbeat_at=now)
            )
            await session.commit()
            return _row_count(result) == 1

    async def release_lease(self, owner_id: str) -> None:
        async with self._session() as session:
            await session.execute(
                delete(_WorkerLeaseRow).where(
                    _WorkerLeaseRow.name == 'executor',
                    _WorkerLeaseRow.owner_id == owner_id,
                )
            )
            await session.commit()

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        await self.initialize()
        async with _database_for(self.database).session() as session:
            yield session

    @staticmethod
    def _record(row: _RunRecordRow, *, result_count: int | None = None) -> dict[str, object]:
        record: dict[str, object] = {
            'run_id': row.run_id,
            'target': row.target,
            'status': row.status,
            'origin': row.origin,
            'created_at': row.created_at,
            'started_at': row.started_at,
            'completed_at': row.completed_at,
            'request_json': row.request_json,
            'evidence_run_id': row.evidence_run_id,
            'evidence_status': row.evidence_status,
            'cancellation_requested_at': row.cancellation_requested_at,
            'error': row.error,
            'log': row.log,
        }
        if result_count is not None:
            record['result_count'] = int(result_count)
        return record


class ResultStore:
    """Persist enumeration results without exposing SQLAlchemy to callers."""

    def __init__(self, database: str | Path | None = None) -> None:
        self.database = str(Path(database or _DEFAULT_DATABASE).expanduser().resolve())

    async def initialize(self) -> None:
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        try:
            await _database_for(self.database).initialize()
        except SQLAlchemyError as error:
            raise ResultStoreError('Could not initialize result store') from error

    async def save_run(self, result: CompletedResult) -> None:
        run_id = str(result.run_id)
        vhosts_by_hostname: dict[str, list[VirtualHostObservation]] = {}
        for observation in result.virtual_hosts:
            vhosts_by_hostname.setdefault(observation.hostname, []).append(observation)
        network_by_prefix: dict[str, list[NetworkObservation]] = {}
        for network_observation in result.network_observations:
            network_by_prefix.setdefault(network_observation.prefix, []).append(network_observation)
        shodan_by_ip = {observation.ip: observation for observation in result.shodan_hosts}
        takeover_by_hostname = {outcome.hostname: outcome for outcome in result.takeover_outcomes}
        async with self._session() as session:
            try:
                session.add(
                    _RunRow(
                        run_id=run_id,
                        target=result.target,
                        started_at=result.started_at.isoformat(),
                        completed_at=result.completed_at.isoformat(),
                        evidence_status=result.evidence_status,
                    )
                )
                await session.flush()
                session.add_all(
                    _ResultRow(
                        run_id=run_id,
                        position=position,
                        kind=kind,
                        value=value,
                        details_json=(
                            json.dumps(
                                virtual_host_details(vhosts_by_hostname[value]),
                                ensure_ascii=False,
                                separators=(',', ':'),
                                sort_keys=True,
                            )
                            if kind == 'hostname' and value in vhosts_by_hostname
                            else json.dumps(
                                network_observation_details(tuple(network_by_prefix[value])),
                                ensure_ascii=False,
                                separators=(',', ':'),
                                sort_keys=True,
                            )
                            if kind == 'prefix' and value in network_by_prefix
                            else json.dumps(
                                shodan_by_ip[value].to_details(),
                                ensure_ascii=False,
                                separators=(',', ':'),
                                sort_keys=True,
                            )
                            if kind == 'shodan-host' and value in shodan_by_ip
                            else json.dumps(
                                takeover_by_hostname[value].to_details(),
                                ensure_ascii=False,
                                separators=(',', ':'),
                                sort_keys=True,
                            )
                            if kind == 'takeover' and value in takeover_by_hostname
                            else None
                        ),
                    )
                    for position, (kind, value) in enumerate(result.results)
                )
                producers: list[tuple[str, str, SourceExecution | ActionExecution]] = [
                    ('source', execution.source, execution) for execution in result.source_executions
                ]
                producers.extend(('action', execution.action, execution) for execution in result.active_evidence.executions)
                session.add_all(
                    _ExecutionRow(
                        run_id=run_id,
                        position=position,
                        producer_kind=producer_kind,
                        name=name,
                        status=execution.status,
                        duration_ms=execution.duration_ms,
                        result_count=execution.result_count,
                        error_type=execution.error_type,
                        stop_reason=execution.stop_reason,
                    )
                    for position, (producer_kind, name, execution) in enumerate(producers)
                )
                await session.flush()
                result_positions = {item: position for position, item in enumerate(result.results)}
                execution_positions = {
                    (producer_kind, name): position for position, (producer_kind, name, _execution) in enumerate(producers)
                }
                origins: list[tuple[str, str, ResultKind, str]] = [
                    ('source', observation.source, observation.kind, observation.value) for observation in result.observations
                ]
                origins.extend(
                    ('action', action, observation.kind, observation.value)
                    for action, observation in result.active_evidence.observations
                )
                session.add_all(
                    _ResultOriginRow(
                        run_id=run_id,
                        result_position=result_positions[(kind, value)],
                        execution_position=execution_positions[(producer_kind, name)],
                    )
                    for producer_kind, name, kind, value in origins
                )
                session.add_all(
                    _ArtifactRow(
                        run_id=run_id,
                        position=position,
                        result_position=result_positions[(artifact.subject_kind, artifact.subject_value)],
                        execution_position=execution_positions[('action', action)],
                        kind=artifact.kind,
                        path=artifact.path,
                        media_type=artifact.media_type,
                        size_bytes=artifact.size_bytes,
                        sha256=artifact.sha256,
                        created_at=artifact.created_at.isoformat(),
                    )
                    for position, (action, artifact) in enumerate(result.active_evidence.artifacts)
                )
                session.add_all(
                    _AsnAttributionRow(
                        run_id=run_id,
                        position=position,
                        asn_result_position=result_positions[('asn', attribution.asn)],
                        subject_result_position=result_positions[(attribution.subject_kind, attribution.subject_value)],
                        execution_position=execution_positions[(attribution.producer_kind, attribution.producer)],
                        organization_label=attribution.organization_label,
                        collected_at=attribution.collected_at.isoformat(),
                    )
                    for position, attribution in enumerate(result.asn_attributions)
                )
                await session.commit()
            except IntegrityError as error:
                duplicate_codes = {
                    sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                    sqlite3.SQLITE_CONSTRAINT_UNIQUE,
                }
                if getattr(error.orig, 'sqlite_errorcode', None) in duplicate_codes:
                    raise DuplicateRunError(f'Enumeration run already exists: {run_id}') from error
                raise ResultStoreError('Could not save enumeration run') from error

    async def load_run(self, run_id: UUID) -> CompletedResult:
        async with self._session() as session:
            parent = await session.get(_RunRow, str(run_id))
            if parent is None:
                raise LookupError(f'completed result not found: {run_id}')
            rows = (
                await session.scalars(select(_ResultRow).where(_ResultRow.run_id == str(run_id)).order_by(_ResultRow.position))
            ).all()
            execution_rows = (
                await session.scalars(
                    select(_ExecutionRow).where(_ExecutionRow.run_id == str(run_id)).order_by(_ExecutionRow.position)
                )
            ).all()
            origin_rows = (await session.scalars(select(_ResultOriginRow).where(_ResultOriginRow.run_id == str(run_id)))).all()
            artifact_rows = (
                await session.scalars(
                    select(_ArtifactRow).where(_ArtifactRow.run_id == str(run_id)).order_by(_ArtifactRow.position)
                )
            ).all()
            attribution_rows = (
                await session.scalars(
                    select(_AsnAttributionRow)
                    .where(_AsnAttributionRow.run_id == str(run_id))
                    .order_by(_AsnAttributionRow.position)
                )
            ).all()
        results_by_position = {row.position: row for row in rows}
        executions_by_position = {row.position: row for row in execution_rows}
        vhost_execution_positions = {
            row.position for row in execution_rows if row.producer_kind == 'action' and row.name == 'vhost'
        }
        vhost_result_positions = {
            row.result_position for row in origin_rows if row.execution_position in vhost_execution_positions
        }
        virtual_hosts: list[VirtualHostObservation] = []
        network_observations: list[NetworkObservation] = []
        shodan_hosts: list[ShodanHostObservation] = []
        takeover_outcomes: list[TakeoverCandidateOutcome] = []
        for result_row in rows:
            has_vhost_provenance = result_row.position in vhost_result_positions
            if has_vhost_provenance:
                if result_row.kind != 'hostname' or result_row.details_json is None:
                    raise ResultStoreError(f'Persisted virtual-host details are missing: {result_row.value}')
                try:
                    details = json.loads(result_row.details_json)
                    parsed_virtual_hosts = parse_virtual_host_details(result_row.value, details)
                except (json.JSONDecodeError, ValueError) as error:
                    raise ResultStoreError(f'Persisted virtual-host details are invalid: {result_row.value}') from error
                if details != virtual_host_details(parsed_virtual_hosts):
                    raise ResultStoreError(f'Persisted virtual-host details are not canonical: {result_row.value}')
                virtual_hosts.extend(parsed_virtual_hosts)
                continue
            if result_row.kind == 'shodan-host':
                if result_row.details_json is None:
                    raise ResultStoreError(f'Persisted Shodan host details are missing: {result_row.value}')
                try:
                    details = json.loads(result_row.details_json)
                    shodan_host = ShodanHostObservation.from_record(result_row.value, details)
                except (json.JSONDecodeError, ValueError) as error:
                    raise ResultStoreError(f'Persisted Shodan host details are invalid: {result_row.value}') from error
                if shodan_host.to_details() != details:
                    raise ResultStoreError(f'Persisted Shodan host details are not canonical: {result_row.value}')
                shodan_hosts.append(shodan_host)
                continue
            if result_row.kind == 'takeover':
                if result_row.details_json is None:
                    raise ResultStoreError(f'Persisted takeover details are missing: {result_row.value}')
                try:
                    details = json.loads(result_row.details_json)
                    takeover_outcome = parse_takeover_details(result_row.value, details)
                except (json.JSONDecodeError, ValueError) as error:
                    raise ResultStoreError(f'Persisted takeover details are invalid: {result_row.value}') from error
                if takeover_outcome.to_details() != details:
                    raise ResultStoreError(f'Persisted takeover details are not canonical: {result_row.value}')
                takeover_outcomes.append(takeover_outcome)
                continue
            if result_row.details_json is None:
                continue
            if result_row.kind == 'prefix':
                try:
                    parsed_network_observations = parse_network_observation_json(
                        result_row.value,
                        result_row.details_json,
                    )
                except ValueError as error:
                    raise ResultStoreError(f'Persisted network details are invalid: {result_row.value}') from error
                network_observations.extend(parsed_network_observations)
            elif result_row.kind == 'hostname':
                raise ResultStoreError('Persisted virtual-host details require hostname results with vhost provenance')
            else:
                raise ResultStoreError('Persisted structured details require a supported result kind and provenance')
        unknown_producer_kinds = {row.producer_kind for row in execution_rows} - {'source', 'action'}
        if unknown_producer_kinds:
            raise ResultStoreError(f'Unknown persisted producer kind: {min(unknown_producer_kinds)}')
        observations_by_execution: dict[int, list[ActionObservation]] = {}
        source_observations: list[ResultObservation] = []
        for origin in origin_rows:
            execution = executions_by_position[origin.execution_position]
            stored_result = results_by_position[origin.result_position]
            if execution.producer_kind == 'source':
                source_observations.append(
                    ResultObservation(
                        source=execution.name,
                        kind=cast('ResultKind', stored_result.kind),
                        value=stored_result.value,
                    )
                )
            else:
                observations_by_execution.setdefault(execution.position, []).append(
                    ActionObservation(
                        kind=cast('ResultKind', stored_result.kind),
                        value=stored_result.value,
                    )
                )
        artifacts_by_execution: dict[int, list[ArtifactReference]] = {}
        for artifact in artifact_rows:
            execution = executions_by_position[artifact.execution_position]
            if execution.producer_kind != 'action':
                raise ResultStoreError('Persisted artifact must reference an action execution')
            subject = results_by_position[artifact.result_position]
            artifacts_by_execution.setdefault(execution.position, []).append(
                ArtifactReference(
                    kind=artifact.kind,
                    subject_kind=cast('ResultKind', subject.kind),
                    subject_value=subject.value,
                    path=artifact.path,
                    media_type=artifact.media_type,
                    size_bytes=artifact.size_bytes,
                    sha256=artifact.sha256,
                    created_at=datetime.datetime.fromisoformat(artifact.created_at),
                )
            )
        action_executions: list[ActionExecution] = []
        for execution_row in execution_rows:
            if execution_row.producer_kind != 'action':
                continue
            action_observations = tuple(sorted(observations_by_execution.get(execution_row.position, [])))
            if execution_row.result_count != len(action_observations):
                raise ResultStoreError(f'Persisted action result count does not match origins: {execution_row.name}')
            action_executions.append(
                ActionExecution(
                    action=execution_row.name,
                    status=cast('ExecutionStatus', execution_row.status),
                    duration_ms=execution_row.duration_ms,
                    observations=action_observations,
                    artifacts=tuple(sorted(artifacts_by_execution.get(execution_row.position, []))),
                    error_type=execution_row.error_type,
                    stop_reason=execution_row.stop_reason,
                )
            )
        asn_attributions: list[AsnAttributionObservation] = []
        for attribution in attribution_rows:
            asn_result = results_by_position.get(attribution.asn_result_position)
            subject_result = results_by_position.get(attribution.subject_result_position)
            attribution_execution = executions_by_position.get(attribution.execution_position)
            if asn_result is None or subject_result is None or attribution_execution is None:
                raise ResultStoreError('Persisted ASN attribution references missing evidence')
            if (
                asn_result.kind != 'asn'
                or attribution_execution.producer_kind not in {'source', 'action'}
                or subject_result.kind not in {'hostname', 'ip'}
            ):
                raise ResultStoreError('Persisted ASN attribution is invalid')
            producer_kind: ProducerKind = 'source' if attribution_execution.producer_kind == 'source' else 'action'
            subject_kind: SubjectKind = 'hostname' if subject_result.kind == 'hostname' else 'ip'
            try:
                asn_attributions.append(
                    AsnAttributionObservation(
                        producer_kind,
                        attribution_execution.name,
                        asn_result.value,
                        attribution.organization_label,
                        subject_kind,
                        subject_result.value,
                        datetime.datetime.fromisoformat(attribution.collected_at),
                    )
                )
            except ValueError as error:
                raise ResultStoreError('Persisted ASN attribution is invalid') from error
        canonical_attributions = canonical_asn_attributions(asn_attributions)
        if tuple(asn_attributions) != canonical_attributions:
            raise ResultStoreError('Persisted ASN attribution is invalid')
        return CompletedResult(
            run_id=UUID(parent.run_id),
            target=parent.target,
            started_at=datetime.datetime.fromisoformat(parent.started_at),
            completed_at=datetime.datetime.fromisoformat(parent.completed_at),
            results=tuple((cast('ResultKind', row.kind), row.value) for row in rows),
            source_executions=tuple(
                SourceExecution(
                    source=row.name,
                    status=cast('ExecutionStatus', row.status),
                    duration_ms=row.duration_ms,
                    result_count=row.result_count,
                    error_type=row.error_type,
                    stop_reason=row.stop_reason,
                )
                for row in execution_rows
                if row.producer_kind == 'source'
            ),
            observations=tuple(sorted(source_observations)),
            active_evidence=ActiveEvidence(executions=tuple(action_executions)),
            virtual_hosts=tuple(sorted(set(virtual_hosts), key=VirtualHostObservation.sort_key)),
            network_observations=tuple(sorted(set(network_observations), key=network_observation_sort_key)),
            asn_attributions=canonical_attributions,
            shodan_hosts=canonical_shodan_hosts(shodan_hosts),
            takeover_outcomes=canonical_takeover_outcomes(takeover_outcomes),
            evidence_status=cast('EvidenceStatus', parent.evidence_status) if parent.evidence_status is not None else None,
        )

    async def list_runs(self, *, limit: int | None = 50, offset: int = 0) -> list[dict[str, object]]:
        async with self._session() as session:
            statement = (
                select(_RunRow, func.count(_ResultRow.position))
                .outerjoin(_ResultRow, _ResultRow.run_id == _RunRow.run_id)
                .group_by(_RunRow.run_id)
                .order_by(func.julianday(_RunRow.completed_at).desc(), _RunRow.run_id.desc())
            )
            if limit is not None:
                statement = statement.limit(limit)
            statement = statement.offset(offset)
            rows = (await session.execute(statement)).all()
        return [
            {
                'run_id': run.run_id,
                'target': run.target,
                'started_at': run.started_at,
                'completed_at': run.completed_at,
                'result_count': result_count,
            }
            for run, result_count in rows
        ]

    async def export_database(self, destination: Path) -> None:
        """Write every completed run to a portable, importable SQLite database."""
        await self.initialize()
        exported = ResultStore(destination)
        try:
            await exported.initialize()
            summaries = await self.list_runs(limit=None)
            for summary in summaries:
                await exported.save_run(await self.load_run(UUID(str(summary['run_id']))))
        finally:
            await exported.dispose()
        await asyncio.to_thread(_finalize_portable_database, destination)
        await exported.validate_import_database()

    async def validate_import_database(self) -> None:
        engine = create_async_engine(URL.create('sqlite+aiosqlite', database=self.database))
        try:
            async with engine.connect() as connection:
                quick_check = await connection.exec_driver_sql('PRAGMA quick_check')
                if quick_check.scalar_one() != 'ok':
                    raise ResultStoreError('SQLite integrity check failed')
                version = (await connection.exec_driver_sql('PRAGMA user_version')).scalar_one()
                if version > SCHEMA_VERSION:
                    raise ResultStoreError(f'Database schema version {version} is newer than supported version {SCHEMA_VERSION}')
                table_rows = await connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type = 'table'")
                tables = {str(row[0]) for row in table_rows}
                current_schema = {'runs', 'results'}.issubset(tables)
                released_schema = {'completed_results', 'completed_result_items'}.issubset(tables)
                if not current_schema and not released_schema:
                    raise ResultStoreError('SQLite database does not contain theHarvester completed runs')
        except SQLAlchemyError as error:
            raise ResultStoreError('Could not validate SQLite database') from error
        finally:
            await engine.dispose()

    async def dispose(self) -> None:
        database = _databases.pop(self.database, None)
        if database is not None:
            await database.dispose()

    async def record_observations(
        self,
        target: str,
        values: Iterable[object],
        kind: ResultKind,
        source: str,
    ) -> None:
        try:
            async with self._session() as session:
                session.add_all(
                    _LegacyObservationRow(
                        domain=target,
                        resource=str(value),
                        kind=kind,
                        discovered_on=datetime.date.today(),
                        source=source,
                    )
                    for value in values
                )
                await session.commit()
        except Exception as error:
            logger.info(f'Unexpected error while storing result: {error}')

    async def source_yields(self, run_id: UUID, *, kind: ResultKind | None = None) -> list[SourceYield]:
        """Count each source's observed, unique, and shared results for a run.

        A result is unique when one source reported it and shared when more than one
        source reported it. Sources that ran without matching results still appear with
        zero counts.
        """
        yields = await self._producer_yields(run_id, 'source', kind=kind)
        return [
            SourceYield(
                source=name,
                observed_result_count=observed,
                unique_result_count=unique,
                shared_result_count=shared,
                resolved_hostname_count=resolved,
                unique_resolved_hostname_count=unique_resolved,
            )
            for name, observed, unique, shared, resolved, unique_resolved in yields
        ]

    async def load_hostname_tracking_run(self, run_id: UUID) -> TrackingRunEvidence:
        """Load only the persisted evidence needed for hostname change tracking."""
        async with self._session() as session:
            parent = await session.get(_RunRow, str(run_id))
            execution_rows = (await session.scalars(select(_ExecutionRow).where(_ExecutionRow.run_id == str(run_id)))).all()
            result_rows = (await session.scalars(select(_ResultRow).where(_ResultRow.run_id == str(run_id)))).all()
            origin_rows = (await session.scalars(select(_ResultOriginRow).where(_ResultOriginRow.run_id == str(run_id)))).all()
        if parent is None:
            raise LookupError(f'completed result not found: {run_id}')
        executions = {row.position: row for row in execution_rows}
        results = {row.position: row for row in result_rows}
        hostname_sources: dict[str, set[str]] = {}
        resolved_hostnames: set[str] = set()
        for origin in origin_rows:
            execution = executions.get(origin.execution_position)
            result = results.get(origin.result_position)
            if execution is None or result is None or result.kind != 'hostname':
                continue
            if execution.producer_kind == 'source':
                hostname_sources.setdefault(result.value, set()).add(execution.name)
            elif execution.producer_kind == 'action' and execution.name == 'dns-resolve':
                resolved_hostnames.add(result.value)
        addressability: dict[str, str] = {}
        allowed_addressability = {value.value for value in Addressability}
        for result in result_rows:
            if result.kind != 'dns-recursive-classification':
                continue
            try:
                classification = json.loads(result.value)
            except json.JSONDecodeError, TypeError:
                continue
            if (
                isinstance(classification, dict)
                and isinstance(classification.get('hostname'), str)
                and classification.get('addressability') in allowed_addressability
            ):
                addressability[classification['hostname']] = classification['addressability']
        source_outcomes = tuple(
            TrackingSourceOutcome(
                source=row.name,
                status=cast('ExecutionStatus', row.status),
                error_type=row.error_type,
                stop_reason=row.stop_reason,
            )
            for row in sorted(execution_rows, key=lambda row: row.name)
            if row.producer_kind == 'source'
        )
        dns_execution = next(
            (row for row in execution_rows if row.producer_kind == 'action' and row.name == 'dns-resolve'),
            None,
        )
        return TrackingRunEvidence(
            run_id=UUID(parent.run_id),
            target=parent.target,
            completed_at=datetime.datetime.fromisoformat(parent.completed_at),
            source_outcomes=source_outcomes,
            hostname_sources=tuple((hostname, tuple(sorted(sources))) for hostname, sources in sorted(hostname_sources.items())),
            resolved_hostnames=frozenset(resolved_hostnames),
            dns_action_status=cast('ExecutionStatus', dns_execution.status) if dns_execution else None,
            addressability=tuple(sorted(addressability.items())),
        )

    async def action_yields(self, run_id: UUID) -> list[ActionYield]:
        yields = await self._producer_yields(run_id, 'action')
        return [
            ActionYield(
                action=name,
                observed_result_count=observed,
                unique_result_count=unique,
                shared_result_count=shared,
            )
            for name, observed, unique, shared, _resolved, _unique_resolved in yields
        ]

    async def _producer_yields(
        self,
        run_id: UUID,
        producer_kind: str,
        *,
        kind: ResultKind | None = None,
    ) -> list[tuple[str, int, int, int, int, int]]:
        async with self._session() as session:
            execution_rows = (await session.scalars(select(_ExecutionRow).where(_ExecutionRow.run_id == str(run_id)))).all()
            result_query = select(_ResultRow).where(_ResultRow.run_id == str(run_id))
            if kind is not None:
                result_query = result_query.where(_ResultRow.kind == kind)
            result_rows = (await session.scalars(result_query)).all()
            origin_rows = (await session.scalars(select(_ResultOriginRow).where(_ResultOriginRow.run_id == str(run_id)))).all()
        producer_by_position = {row.position: row.name for row in execution_rows if row.producer_kind == producer_kind}
        dns_resolution_positions = {
            row.position for row in execution_rows if row.producer_kind == 'action' and row.name == 'dns-resolve'
        }
        result_by_position = {row.position: (row.kind, row.value) for row in result_rows}
        resolved_hostnames = {
            result
            for origin in origin_rows
            if origin.execution_position in dns_resolution_positions
            and (result := result_by_position.get(origin.result_position)) is not None
            and result[0] == 'hostname'
        }
        producers_by_result: dict[tuple[str, str], set[str]] = {}
        for origin in origin_rows:
            producer = producer_by_position.get(origin.execution_position)
            result = result_by_position.get(origin.result_position)
            if producer is not None and result is not None:
                producers_by_result.setdefault(result, set()).add(producer)
        observed_counts: Counter[str] = Counter()
        unique_counts: Counter[str] = Counter()
        shared_counts: Counter[str] = Counter()
        resolved_counts: Counter[str] = Counter()
        unique_resolved_counts: Counter[str] = Counter()
        for result, producers in producers_by_result.items():
            for producer in producers:
                observed_counts[producer] += 1
                (unique_counts if len(producers) == 1 else shared_counts)[producer] += 1
                if result in resolved_hostnames:
                    resolved_counts[producer] += 1
                    if len(producers) == 1:
                        unique_resolved_counts[producer] += 1
        return [
            (
                name,
                observed_counts[name],
                unique_counts[name],
                shared_counts[name],
                resolved_counts[name],
                unique_resolved_counts[name],
            )
            for name in sorted(producer_by_position.values())
        ]

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        try:
            async with _database_for(self.database).session() as session:
                yield session
        except SQLAlchemyError as error:
            raise ResultStoreError('Could not access result store') from error


async def dispose_sqlite_databases() -> None:
    databases = tuple(_databases.values())
    _databases.clear()
    await asyncio.gather(*(database.dispose() for database in databases))
