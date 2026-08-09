import asyncio
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import Date, ForeignKey, Text, UniqueConstraint, event
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA_VERSION = 1


def _sqlite_has_wal_reset_fix(version: tuple[int, int, int]) -> bool:
    return (
        version >= (3, 51, 3)
        or (version[:2] == (3, 50) and version >= (3, 50, 7))
        or (version[:2] == (3, 44) and version >= (3, 44, 6))
    )


class Base(DeclarativeBase):
    pass


class DiscoveryObservationRecord(Base):
    """One source's observation of a resource during an enumeration run."""

    __tablename__ = 'discovery_observations'

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(Text, index=True)
    resource: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text, index=True)
    discovered_on: Mapped[date] = mapped_column(Date, index=True)
    source: Mapped[str] = mapped_column(Text)


class CompletedRunRecord(Base):
    """The target and timestamps shared by the evidence from one completed run."""

    __tablename__ = 'completed_results'

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    target: Mapped[str] = mapped_column(Text)
    started_at: Mapped[str] = mapped_column(Text)
    completed_at: Mapped[str] = mapped_column(Text)


class CompletedResultItemRecord(Base):
    """A deduplicated finding in a completed run, kept in output order."""

    __tablename__ = 'completed_result_items'
    __table_args__ = (UniqueConstraint('run_id', 'kind', 'value'),)

    run_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey('completed_results.run_id', ondelete='CASCADE'),
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


class SQLiteDatabase:
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
                        await connection.run_sync(Base.metadata.create_all)
                        legacy_table = await connection.exec_driver_sql(
                            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'results'"
                        )
                        if legacy_table.scalar_one_or_none() is not None:
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
                                'ELSE type END, find_date, source FROM results'
                            )
                            await connection.exec_driver_sql('DROP TABLE results')
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
            self._initialized = True

    async def dispose(self) -> None:
        await self.engine.dispose()


_databases: dict[str, SQLiteDatabase] = {}


def _database_for(database: str | Path) -> SQLiteDatabase:
    path = str(Path(database).expanduser().resolve())
    if path not in _databases:
        _databases[path] = SQLiteDatabase(path)
    return _databases[path]


@asynccontextmanager
async def sqlite_session(database: str | Path) -> AsyncIterator[AsyncSession]:
    async with _database_for(database).session() as session:
        yield session


async def initialize_stash_schema(database: str | Path) -> None:
    await _database_for(database).initialize()


async def dispose_sqlite_databases() -> None:
    databases = tuple(_databases.values())
    _databases.clear()
    await asyncio.gather(*(database.dispose() for database in databases))
