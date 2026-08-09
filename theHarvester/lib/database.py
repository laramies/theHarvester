import asyncio
import datetime
import logging
import sqlite3
from collections import Counter
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import CheckConstraint, Date, Float, ForeignKey, ForeignKeyConstraint, Text, UniqueConstraint, event, func, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from theHarvester.lib.active_evidence import (
    ActionExecution,
    ActionObservation,
    ActionYield,
    ActiveEvidence,
    ArtifactReference,
)
from theHarvester.lib.completed_result import (
    CompletedResult,
    ExecutionStatus,
    ResultKind,
    ResultObservation,
    SourceExecution,
    SourceYield,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 3
_DEFAULT_DATABASE = Path('~/.local/share/theHarvester/stash.sqlite').expanduser()


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


def _configure_sqlite_connection(dbapi_connection: Any, _connection_record: Any) -> None:
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.close()


def _begin_sqlite_transaction(connection: Any) -> None:
    connection.exec_driver_sql('BEGIN')


def _sqlite_engine(database: str | Path) -> AsyncEngine:
    engine = create_async_engine(
        URL.create('sqlite+aiosqlite', database=str(Path(database).expanduser().resolve())),
        connect_args={'autocommit': sqlite3.LEGACY_TRANSACTION_CONTROL, 'timeout': 30},
    )
    event.listen(engine.sync_engine, 'connect', _configure_sqlite_connection)
    event.listen(engine.sync_engine, 'begin', _begin_sqlite_transaction)
    return engine


class _SQLiteDatabase:
    def __init__(self, database: str | Path) -> None:
        self.database = str(Path(database).expanduser().resolve())
        self.engine = _sqlite_engine(database)
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
                        if has_legacy_results:
                            await connection.exec_driver_sql(
                                'INSERT INTO legacy_observations (domain, resource, kind, discovered_on, source) '
                                'SELECT domain, resource, CASE type '
                                "WHEN 'host' THEN 'hostname' "
                                "WHEN 'ip' THEN 'ip-address' "
                                "WHEN 'people' THEN 'person' "
                                "WHEN 'linkedinlinks' THEN 'linkedin-link' "
                                "WHEN 'interestingurls' THEN 'interesting-url' "
                                "WHEN 'asns' THEN 'asn' "
                                "WHEN 'api_endpoint' THEN 'api-endpoint' "
                                'ELSE type END, find_date, source FROM legacy_results'
                            )
                            await connection.exec_driver_sql('DROP TABLE legacy_results')
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
        async with self._session() as session:
            try:
                session.add(
                    _RunRow(
                        run_id=run_id,
                        target=result.target,
                        started_at=result.started_at.isoformat(),
                        completed_at=result.completed_at.isoformat(),
                    )
                )
                await session.flush()
                session.add_all(
                    _ResultRow(run_id=run_id, position=position, kind=kind, value=value)
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
        results_by_position = {row.position: row for row in rows}
        executions_by_position = {row.position: row for row in execution_rows}
        unknown_producer_kinds = {row.producer_kind for row in execution_rows} - {'source', 'action'}
        if unknown_producer_kinds:
            raise ResultStoreError(f'Unknown persisted producer kind: {sorted(unknown_producer_kinds)[0]}')
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
        for row in execution_rows:
            if row.producer_kind != 'action':
                continue
            action_observations = tuple(sorted(observations_by_execution.get(row.position, [])))
            if row.result_count != len(action_observations):
                raise ResultStoreError(f'Persisted action result count does not match origins: {row.name}')
            action_executions.append(
                ActionExecution(
                    action=row.name,
                    status=cast('ExecutionStatus', row.status),
                    duration_ms=row.duration_ms,
                    observations=action_observations,
                    artifacts=tuple(sorted(artifacts_by_execution.get(row.position, []))),
                    error_type=row.error_type,
                    stop_reason=row.stop_reason,
                )
            )
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
        )

    async def list_runs(self, *, limit: int = 50) -> list[dict[str, object]]:
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(_RunRow, func.count(_ResultRow.position))
                    .outerjoin(_ResultRow, _ResultRow.run_id == _RunRow.run_id)
                    .group_by(_RunRow.run_id)
                    .order_by(func.julianday(_RunRow.completed_at).desc(), _RunRow.run_id.desc())
                    .limit(limit)
                )
            ).all()
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

    async def source_yields(self, run_id: UUID) -> list[SourceYield]:
        """Count each source's observed, unique, and shared results for a run.

        A result is unique when one source reported it and shared when more than one
        source reported it. Sources that ran without results still appear with zero counts.
        """
        yields = await self._producer_yields(run_id, 'source')
        return [
            SourceYield(
                source=name,
                observed_result_count=observed,
                unique_result_count=unique,
                shared_result_count=shared,
            )
            for name, observed, unique, shared in yields
        ]

    async def action_yields(self, run_id: UUID) -> list[ActionYield]:
        yields = await self._producer_yields(run_id, 'action')
        return [
            ActionYield(
                action=name,
                observed_result_count=observed,
                unique_result_count=unique,
                shared_result_count=shared,
            )
            for name, observed, unique, shared in yields
        ]

    async def _producer_yields(self, run_id: UUID, producer_kind: str) -> list[tuple[str, int, int, int]]:
        async with self._session() as session:
            execution_rows = (
                await session.scalars(
                    select(_ExecutionRow).where(
                        _ExecutionRow.run_id == str(run_id),
                        _ExecutionRow.producer_kind == producer_kind,
                    )
                )
            ).all()
            result_rows = (await session.scalars(select(_ResultRow).where(_ResultRow.run_id == str(run_id)))).all()
            origin_rows = (await session.scalars(select(_ResultOriginRow).where(_ResultOriginRow.run_id == str(run_id)))).all()
        producer_by_position = {row.position: row.name for row in execution_rows}
        result_by_position = {row.position: (row.kind, row.value) for row in result_rows}
        producers_by_result: dict[tuple[str, str], set[str]] = {}
        for origin in origin_rows:
            producer = producer_by_position.get(origin.execution_position)
            result = result_by_position.get(origin.result_position)
            if producer is not None and result is not None:
                producers_by_result.setdefault(result, set()).add(producer)
        observed_counts: Counter[str] = Counter()
        unique_counts: Counter[str] = Counter()
        shared_counts: Counter[str] = Counter()
        for producers in producers_by_result.values():
            for producer in producers:
                observed_counts[producer] += 1
                (unique_counts if len(producers) == 1 else shared_counts)[producer] += 1
        return [
            (name, observed_counts[name], unique_counts[name], shared_counts[name])
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
