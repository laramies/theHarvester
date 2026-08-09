import asyncio
import datetime
import logging
import sqlite3
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Date, ForeignKey, Text, UniqueConstraint, event, func, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from theHarvester.lib.completed_result import CompletedResult, ResultKind

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
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


class _DiscoveryObservationRow(_Base):
    """A runless source observation, including incomplete rows from older databases."""

    __tablename__ = 'discovery_observations'

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
                            has_legacy_results = 'results' in tables
                            if has_legacy_results:
                                await connection.exec_driver_sql('ALTER TABLE results RENAME TO legacy_results')
                            if 'completed_results' in tables:
                                await connection.exec_driver_sql('ALTER TABLE completed_results RENAME TO runs')
                            if 'completed_result_items' in tables:
                                await connection.exec_driver_sql('ALTER TABLE completed_result_items RENAME TO results')
                        await connection.run_sync(_Base.metadata.create_all)
                        if has_legacy_results:
                            await connection.exec_driver_sql(
                                'INSERT INTO discovery_observations (domain, resource, kind, discovered_on, source) '
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
        return CompletedResult(
            run_id=UUID(parent.run_id),
            target=parent.target,
            started_at=datetime.datetime.fromisoformat(parent.started_at),
            completed_at=datetime.datetime.fromisoformat(parent.completed_at),
            results=tuple((cast('ResultKind', row.kind), row.value) for row in rows),
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
                    _DiscoveryObservationRow(
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
