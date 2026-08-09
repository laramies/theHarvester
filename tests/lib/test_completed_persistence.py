import asyncio
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from theHarvester.lib import database as database_module
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.database import (
    DuplicateRunError,
    ResultStore,
    ResultStoreError,
    _sqlite_has_wal_reset_fix,
    dispose_sqlite_databases,
)

RELEASED_COMPLETED_SCHEMA = """
CREATE TABLE completed_results (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL
);
CREATE TABLE completed_result_items (
    run_id TEXT NOT NULL REFERENCES completed_results(run_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (run_id, position),
    UNIQUE (run_id, kind, value)
);
"""

RELEASED_RESULTS_SCHEMA = """
CREATE TABLE results (
    domain TEXT,
    resource TEXT,
    type TEXT,
    find_date DATE,
    source TEXT
);
"""


def completed_result(run_id: str = 'f047261c-0afb-4e18-89d5-28a7d977f51f') -> CompletedResult:
    return CompletedResult.finish(
        run_id=UUID(run_id),
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={
            'breach': ['ExampleBreach'],
            'dns-recursive-finding': ['{"addresses":["192.0.2.2"],"hostname":"dev.api.example.com","parent":"api.example.com"}'],
            'dns-recursive-classification': [
                '{"addressability":"not-currently-addressable","addresses":[],"cnames":["missing.vendor.test"],"hostname":"unused.api.example.com","parent":"api.example.com"}'
            ],
            'dns-recursive-summary': ['{"depth_reached":1,"query_count":24,"stop_reason":"depth-limit","zero_yield_batches":0}'],
            'hostname': ['api.example.com'],
            'ip-address': ['192.0.2.1'],
            'person': ['{"firstname":"Ada","lastname":"Lovelace"}'],
        },
    )


@pytest.mark.asyncio
async def test_initialization_enables_wal_when_sqlite_contains_the_reset_fix(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)

    await store.initialize()

    with sqlite3.connect(database) as db:
        journal_mode = db.execute('PRAGMA journal_mode').fetchone()[0]
    expected_mode = 'wal' if _sqlite_has_wal_reset_fix(sqlite3.sqlite_version_info) else 'delete'
    assert journal_mode == expected_mode


@pytest.mark.parametrize(
    ('version', 'expected'),
    [
        ((3, 44, 5), False),
        ((3, 44, 6), True),
        ((3, 50, 6), False),
        ((3, 50, 7), True),
        ((3, 51, 2), False),
        ((3, 51, 3), True),
    ],
)
def test_wal_reset_fix_version_boundaries(version: tuple[int, int, int], expected: bool) -> None:
    assert _sqlite_has_wal_reset_fix(version) is expected


@pytest.mark.asyncio
async def test_initialization_fails_when_runtime_connections_do_not_enforce_foreign_keys(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def configure_without_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        dbapi_connection.isolation_level = None  # type: ignore[attr-defined]

    monkeypatch.setattr(database_module, '_configure_sqlite_connection', configure_without_foreign_keys)
    store = ResultStore(tmp_path / 'stash.sqlite')

    with pytest.raises(RuntimeError, match='foreign-key enforcement'):
        await store.initialize()


@pytest.mark.asyncio
async def test_newer_schema_is_rejected_without_changing_journal_mode(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    with sqlite3.connect(database) as db:
        db.execute('PRAGMA user_version = 2')
        original_journal_mode = db.execute('PRAGMA journal_mode').fetchone()[0]

    with pytest.raises(RuntimeError, match='schema version 2 is newer than supported version 1'):
        await store.initialize()

    with sqlite3.connect(database) as db:
        assert db.execute('PRAGMA journal_mode').fetchone()[0] == original_journal_mode


@pytest.mark.asyncio
async def test_locked_database_write_does_not_block_the_event_loop(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    blocker = sqlite3.connect(database, check_same_thread=False)
    blocker.execute('BEGIN EXCLUSIVE')
    heartbeat_ran = threading.Event()
    heartbeat_seen_before_unlock: list[bool] = []

    def unlock_database() -> None:
        heartbeat_seen_before_unlock.append(heartbeat_ran.is_set())
        blocker.rollback()

    unlock_timer = threading.Timer(0.2, unlock_database)
    unlock_timer.start()
    try:
        write = asyncio.create_task(store.record_observations('example.com', ['api.example.com'], 'hostname', 'crtsh'))
        heartbeat = asyncio.create_task(asyncio.sleep(0, result=None))
        heartbeat.add_done_callback(lambda _task: heartbeat_ran.set())
        await asyncio.gather(write, heartbeat)
    finally:
        unlock_timer.join()
        blocker.close()

    assert heartbeat_seen_before_unlock == [True]


@pytest.mark.asyncio
async def test_schema_enforces_foreign_keys_and_cascades_results(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    result = completed_result()
    await store.save_run(result)

    with sqlite3.connect(database) as db:
        db.execute('PRAGMA foreign_keys = ON')
        assert db.execute('PRAGMA foreign_keys').fetchone()[0] == 1
        db.execute('DELETE FROM runs WHERE run_id = ?', (str(result.run_id),))
        db.commit()
        assert db.execute('SELECT COUNT(*) FROM results').fetchone()[0] == 0


@pytest.mark.asyncio
async def test_completed_result_round_trip_preserves_discovery_observations(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    await store.record_observations('example.com', ['legacy.example.com'], 'hostname', 'legacy-source')
    result = completed_result()

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    with sqlite3.connect(database) as db:
        stored = db.execute('SELECT domain, resource, kind, source FROM discovery_observations').fetchall()
        stored_items = set(db.execute('SELECT kind, value FROM results').fetchall())
        run_types = {row[1]: row[2] for row in db.execute('PRAGMA table_info(runs)')}
        result_types = {row[1]: row[2] for row in db.execute('PRAGMA table_info(results)')}
    jsonl_items = {(record['type'], record['value']) for line in result.jsonl().splitlines()[1:] if (record := json.loads(line))}
    assert stored == [('example.com', 'legacy.example.com', 'hostname', 'legacy-source')]
    assert stored_items == jsonl_items
    assert run_types == {'run_id': 'TEXT', 'target': 'TEXT', 'started_at': 'TEXT', 'completed_at': 'TEXT'}
    assert result_types == {
        'run_id': 'TEXT',
        'position': 'INTEGER',
        'kind': 'TEXT',
        'value': 'TEXT',
    }


@pytest.mark.asyncio
async def test_existing_completed_records_survive_initialization(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    existing = completed_result()
    with sqlite3.connect(database) as db:
        db.executescript(RELEASED_RESULTS_SCHEMA + RELEASED_COMPLETED_SCHEMA)
        db.execute(
            'INSERT INTO results (domain, resource, type, find_date, source) VALUES (?, ?, ?, ?, ?)',
            ('example.com', 'legacy.example.com', 'host', '2026-08-08', 'crtsh'),
        )
        db.execute(
            'INSERT INTO completed_results (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (str(existing.run_id), existing.target, existing.started_at.isoformat(), existing.completed_at.isoformat()),
        )
        db.executemany(
            'INSERT INTO completed_result_items (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            [(str(existing.run_id), position, kind, value) for position, (kind, value) in enumerate(existing.results)],
        )

    await store.initialize()

    assert await store.load_run(existing.run_id) == existing
    with sqlite3.connect(database) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        migrated = db.execute('SELECT resource, kind, source FROM discovery_observations').fetchall()
    assert {'completed_results', 'completed_result_items', 'legacy_results'}.isdisjoint(tables)
    assert migrated == [('legacy.example.com', 'hostname', 'crtsh')]


@pytest.mark.asyncio
async def test_current_schema_reopens_without_running_legacy_migration(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    existing = completed_result()
    await store.initialize()
    await store.save_run(existing)
    await dispose_sqlite_databases()

    reopened = ResultStore(database)
    await reopened.initialize()

    assert await reopened.load_run(existing.run_id) == existing


@pytest.mark.asyncio
async def test_released_results_migrate_to_discovery_observations(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    released_rows = [
        ('example.com', 'api.example.com', 'host', '2026-08-08', 'crtsh'),
        ('example.com', '192.0.2.1', 'ip', '2026-08-08', 'dns'),
        ('example.com', 'Ada Lovelace', 'people', '2026-08-08', 'hunter'),
        ('example.com', 'https://linkedin.test/ada', 'linkedinlinks', '2026-08-08', 'linkedin'),
        ('example.com', 'https://admin.example.com', 'interestingurls', '2026-08-08', 'builtwith'),
        ('example.com', 'AS64496', 'asns', '2026-08-08', 'shodan'),
        ('example.com', '/api/v1', 'api_endpoint', '2026-08-08', 'api_scan'),
        ('example.com', 'admin@example.com', 'email', '2026-08-08', 'hunter'),
    ]
    with sqlite3.connect(database) as db:
        db.executescript(RELEASED_RESULTS_SCHEMA)
        db.executemany('INSERT INTO results (domain, resource, type, find_date, source) VALUES (?, ?, ?, ?, ?)', released_rows)

    await store.initialize()
    await store.initialize()

    with sqlite3.connect(database) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        observations = db.execute('SELECT resource, kind FROM discovery_observations ORDER BY id').fetchall()
        result_columns = [row[1] for row in db.execute('PRAGMA table_info(results)')]
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert 'legacy_results' not in tables
    assert result_columns == ['run_id', 'position', 'kind', 'value']
    assert observations == [
        ('api.example.com', 'hostname'),
        ('192.0.2.1', 'ip-address'),
        ('Ada Lovelace', 'person'),
        ('https://linkedin.test/ada', 'linkedin-link'),
        ('https://admin.example.com', 'interesting-url'),
        ('AS64496', 'asn'),
        ('/api/v1', 'api-endpoint'),
        ('admin@example.com', 'email'),
    ]
    assert schema_version == 1


@pytest.mark.asyncio
async def test_released_null_observation_fields_survive_migration(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    with sqlite3.connect(database) as db:
        db.executescript(RELEASED_RESULTS_SCHEMA)
        db.execute(
            'INSERT INTO results (domain, resource, type, find_date, source) VALUES (?, ?, ?, ?, ?)',
            (None, None, None, None, None),
        )

    store = ResultStore(database)
    await store.initialize()

    with sqlite3.connect(database) as db:
        migrated = db.execute('SELECT domain, resource, kind, discovered_on, source FROM discovery_observations').fetchall()
    assert migrated == [(None, None, None, None, None)]


@pytest.mark.asyncio
async def test_concurrent_initialization_migrates_released_results_once(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    first = ResultStore(database)
    second = ResultStore(database)
    with sqlite3.connect(database) as db:
        db.executescript(RELEASED_RESULTS_SCHEMA)
        db.execute(
            'INSERT INTO results (domain, resource, type, find_date, source) VALUES (?, ?, ?, ?, ?)',
            ('example.com', 'api.example.com', 'host', '2026-08-08', 'crtsh'),
        )

    await asyncio.gather(first.initialize(), second.initialize())

    with sqlite3.connect(database) as db:
        rows = db.execute('SELECT domain, resource, kind, source FROM discovery_observations').fetchall()
    assert rows == [('example.com', 'api.example.com', 'hostname', 'crtsh')]


@pytest.mark.asyncio
async def test_completed_result_write_is_atomic_and_rejects_duplicate_run_id(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    result = completed_result()
    await store.save_run(result)

    with pytest.raises(DuplicateRunError):
        await store.save_run(result)

    failing = completed_result('f9b33a33-e6d6-4a48-b04f-1a4a3012bc1f')
    with sqlite3.connect(database) as db:
        db.execute(
            """
            CREATE TRIGGER fail_result
            BEFORE INSERT ON results
            WHEN NEW.run_id = 'f9b33a33-e6d6-4a48-b04f-1a4a3012bc1f'
            BEGIN
                SELECT RAISE(ABORT, 'forced failure');
            END
            """
        )

    with pytest.raises(ResultStoreError, match='Could not save enumeration run'):
        await store.save_run(failing)

    with sqlite3.connect(database) as db:
        run_count = db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]
        result_count = db.execute('SELECT COUNT(*) FROM results').fetchone()[0]
    assert (run_count, result_count) == (1, 7)


@pytest.mark.asyncio
async def test_discovery_observations_use_the_normalized_schema(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    await store.record_observations('example.com', ['api.example.com', 'www.example.com'], 'hostname', 'crtsh')
    await store.record_observations('example.com', ['admin@example.com'], 'email', 'hunter')
    await store.record_observations('example.com', ['192.0.2.1'], 'ip-address', 'dns')
    await store.record_observations('example.com', ['{"firstname":"Ada","lastname":"Lovelace"}'], 'person', 'hunter')
    await store.record_observations('example.com', ['vhost.example.com'], 'vhost', 'virtual-host')
    await store.record_observations('example.com', ['443'], 'shodan', 'shodan')

    with sqlite3.connect(database) as db:
        columns = [row[1] for row in db.execute('PRAGMA table_info(discovery_observations)')]
        rows = db.execute('SELECT domain, resource, kind, source FROM discovery_observations ORDER BY id').fetchall()

    assert columns == ['id', 'domain', 'resource', 'kind', 'discovered_on', 'source']
    assert rows == [
        ('example.com', 'api.example.com', 'hostname', 'crtsh'),
        ('example.com', 'www.example.com', 'hostname', 'crtsh'),
        ('example.com', 'admin@example.com', 'email', 'hunter'),
        ('example.com', '192.0.2.1', 'ip-address', 'dns'),
        ('example.com', '{"firstname":"Ada","lastname":"Lovelace"}', 'person', 'hunter'),
        ('example.com', 'vhost.example.com', 'vhost', 'virtual-host'),
        ('example.com', '443', 'shodan', 'shodan'),
    ]


@pytest.mark.asyncio
async def test_completed_results_are_ordered_by_instant_across_offsets(tmp_path) -> None:
    store = ResultStore(tmp_path / 'stash.sqlite')
    await store.initialize()
    earlier = CompletedResult.finish(
        run_id=UUID('32c0630c-4af8-421a-9650-10f1472db591'),
        target='earlier.example',
        started_at=datetime(2025, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=2))),
        completed_at=datetime(2026, 1, 1, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        groups={'hostname': ['earlier.example']},
    )
    later = CompletedResult.finish(
        run_id=UUID('dc0679ee-e52b-4908-8a3c-9ed26ad8f0cc'),
        target='later.example',
        started_at=datetime(2025, 12, 31, 22, 59, tzinfo=UTC),
        completed_at=datetime(2025, 12, 31, 23, 0, tzinfo=UTC),
        groups={'hostname': ['later.example']},
    )
    await store.save_run(earlier)
    await store.save_run(later)

    rows = await store.list_runs()

    assert [row['target'] for row in rows] == ['later.example', 'earlier.example']
