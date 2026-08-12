import asyncio
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from theHarvester.lib import database as database_module
from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence, ArtifactReference
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution
from theHarvester.lib.database import (
    DuplicateRunError,
    ResultStore,
    ResultStoreError,
    _sqlite_has_wal_reset_fix,
    dispose_sqlite_databases,
)
from theHarvester.lib.network_evidence import (
    BgpRouteObservation,
    PrefixOriginObservation,
    RpkiValidationObservation,
    network_observation_details,
)
from theHarvester.lib.virtual_host import VirtualHostObservation

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

SCHEMA_V1_DISCOVERY_OBSERVATIONS = """
CREATE TABLE discovery_observations (
    id INTEGER NOT NULL PRIMARY KEY,
    domain TEXT NOT NULL,
    resource TEXT NOT NULL,
    kind TEXT NOT NULL,
    discovered_on DATE NOT NULL,
    source TEXT NOT NULL
);
PRAGMA user_version = 1;
"""

SCHEMA_V2_RUN_PROVENANCE = """
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL
);
CREATE TABLE results (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (run_id, position),
    UNIQUE (run_id, kind, value)
);
CREATE TABLE executions (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    producer_kind TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    result_count INTEGER NOT NULL,
    error_type TEXT,
    stop_reason TEXT,
    PRIMARY KEY (run_id, position),
    UNIQUE (run_id, producer_kind, name)
);
CREATE TABLE result_origins (
    run_id TEXT NOT NULL,
    result_position INTEGER NOT NULL,
    execution_position INTEGER NOT NULL,
    PRIMARY KEY (run_id, result_position, execution_position),
    FOREIGN KEY (run_id, result_position) REFERENCES results(run_id, position) ON DELETE CASCADE,
    FOREIGN KEY (run_id, execution_position) REFERENCES executions(run_id, position) ON DELETE CASCADE
);
CREATE TABLE legacy_observations (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    resource TEXT,
    kind TEXT,
    discovered_on DATE,
    source TEXT
);
PRAGMA user_version = 2;
"""

SCHEMA_V4_URL_KINDS = (
    SCHEMA_V2_RUN_PROVENANCE
    + """
CREATE TABLE artifacts (
    run_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    result_position INTEGER NOT NULL,
    execution_position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, position),
    FOREIGN KEY (run_id, result_position) REFERENCES results(run_id, position) ON DELETE CASCADE,
    FOREIGN KEY (run_id, execution_position) REFERENCES executions(run_id, position) ON DELETE CASCADE
);
PRAGMA user_version = 4;
"""
)

SCHEMA_V5_RESULT_KINDS = SCHEMA_V4_URL_KINDS + 'PRAGMA user_version = 5;'
SCHEMA_V6_RESULT_KINDS = SCHEMA_V5_RESULT_KINDS + 'PRAGMA user_version = 6;'
SCHEMA_V7_EVIDENCE_STATUS = (
    SCHEMA_V6_RESULT_KINDS
    + """
ALTER TABLE runs ADD COLUMN evidence_status TEXT;
PRAGMA user_version = 7;
"""
)


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
            'ip': ['192.0.2.1'],
            'person': ['{"firstname":"Ada","lastname":"Lovelace"}'],
        },
    )


def screenshot_execution(completed_at: datetime) -> ActionExecution:
    return ActionExecution.finish(
        action='screenshot',
        status='completed',
        duration_ms=4.0,
        groups={},
        artifacts=(
            ArtifactReference(
                kind='screenshot',
                subject_kind='hostname',
                subject_value='api.example.com',
                path='screenshots/api.example.com.png',
                media_type='image/png',
                size_bytes=3,
                sha256='0' * 64,
                created_at=completed_at,
            ),
        ),
    )


def vhost_observation(endpoint: str, *, status: int, control_status: int) -> VirtualHostObservation:
    return VirtualHostObservation.from_record(
        {
            'type': 'vhost',
            'endpoint': endpoint,
            'hostname': 'admin.example.com',
            'http_host': 'admin.example.com',
            'tls_server_name': None,
            'classification': 'distinct',
            'phase': 'body',
            'status': status,
            'location': None,
            'body_sha256': 'a' * 64,
            'body_size': 5,
            'body_truncated': False,
            'context_phase': 'body',
            'context_status': control_status,
            'context_location': None,
            'context_body_sha256': 'a' * 64,
            'context_body_size': 5,
            'context_body_truncated': False,
            'control_phase': 'body',
            'control_status': control_status,
            'control_location': None,
            'control_body_sha256': 'a' * 64,
            'control_body_size': 5,
            'control_body_truncated': False,
            'confirmation_body_sha256': None,
            'tls_verified': None,
            'distinct_signals': ['status'],
            'reflection_normalized': False,
        }
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
        db.execute('PRAGMA user_version = 9')
        original_journal_mode = db.execute('PRAGMA journal_mode').fetchone()[0]

    with pytest.raises(RuntimeError, match='schema version 9 is newer than supported version 8'):
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
async def test_completed_result_round_trip_preserves_legacy_observations(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    await store.record_observations('example.com', ['legacy.example.com'], 'hostname', 'legacy-source')
    result = completed_result()

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    with sqlite3.connect(database) as db:
        stored = db.execute('SELECT domain, resource, kind, source FROM legacy_observations').fetchall()
        stored_items = set(db.execute('SELECT kind, value FROM results').fetchall())
        run_types = {row[1]: row[2] for row in db.execute('PRAGMA table_info(runs)')}
        result_types = {row[1]: row[2] for row in db.execute('PRAGMA table_info(results)')}
    jsonl_items = {(record['type'], record['value']) for line in result.jsonl().splitlines()[1:] if (record := json.loads(line))}
    assert stored == [('example.com', 'legacy.example.com', 'hostname', 'legacy-source')]
    assert stored_items == jsonl_items
    assert run_types == {
        'run_id': 'TEXT',
        'target': 'TEXT',
        'started_at': 'TEXT',
        'completed_at': 'TEXT',
        'evidence_status': 'TEXT',
    }
    assert result_types == {
        'run_id': 'TEXT',
        'position': 'INTEGER',
        'kind': 'TEXT',
        'value': 'TEXT',
        'details_json': 'TEXT',
    }


@pytest.mark.asyncio
async def test_structured_vhost_evidence_round_trips_in_the_results_table(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    completed_at = datetime(2026, 8, 9, 12, 1, tzinfo=UTC)
    first = vhost_observation('http://192.0.2.10', status=200, control_status=404)
    second = vhost_observation('http://192.0.2.11', status=201, control_status=404)
    result = CompletedResult.finish(
        run_id=UUID('3ac7bba2-45da-4cdd-96a4-019a4d42bca4'),
        target='example.com',
        started_at=completed_at,
        completed_at=completed_at,
        groups={},
        source_executions=(SourceExecution('crtsh', 'completed', 4.0, 1),),
        observations=(ResultObservation('crtsh', 'hostname', 'admin.example.com'),),
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='vhost',
                    status='completed',
                    duration_ms=12.5,
                    groups={'hostname': ['admin.example.com']},
                ),
            )
        ),
        virtual_hosts=(second, first),
    )

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    with sqlite3.connect(database) as db:
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
        stored_result = db.execute(
            'SELECT kind, value, details_json FROM results WHERE run_id = ?',
            (str(result.run_id),),
        ).fetchone()
        executions = db.execute(
            'SELECT producer_kind, name, result_count FROM executions WHERE run_id = ? ORDER BY producer_kind',
            (str(result.run_id),),
        ).fetchall()
        origin_count = db.execute(
            'SELECT COUNT(*) FROM result_origins WHERE run_id = ?',
            (str(result.run_id),),
        ).fetchone()[0]
    assert schema_version == 8
    assert stored_result[:2] == ('hostname', 'admin.example.com')
    assert json.loads(stored_result[2]) == [
        {key: value for key, value in observation.to_record().items() if key not in {'type', 'hostname'}}
        for observation in (first, second)
    ]
    assert executions == [('action', 'vhost', 1), ('source', 'crtsh', 1)]
    assert origin_count == 2


@pytest.mark.asyncio
async def test_structured_network_evidence_round_trips_in_the_results_table(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    collected_at = datetime(2026, 8, 11, 12, 1, tzinfo=UTC)
    observed_at = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    network_observations = (
        PrefixOriginObservation('routeviews', '198.51.100.7/24', 64500, collected_at),
        BgpRouteObservation(
            'routeviews',
            '198.51.100.0/24',
            'AS64500',
            'route-views.test',
            64496,
            '192.0.2.7',
            '64496 64500',
            '',
            observed_at,
            collected_at,
        ),
        RpkiValidationObservation(
            'routeviews',
            '198.51.100.0/24',
            64500,
            'not-found',
            observed_at,
            collected_at,
        ),
    )
    result = CompletedResult.finish(
        run_id=UUID('6db84c57-e459-4a5a-95c5-1c231a160ba6'),
        target='example.com',
        started_at=observed_at,
        completed_at=collected_at,
        groups={'asn': ['AS64500']},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='routeviews',
                    status='completed',
                    duration_ms=15,
                    groups={'prefix': ['198.51.100.0/24']},
                ),
            )
        ),
        network_observations=network_observations,
    )

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    with sqlite3.connect(database) as db:
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
        stored_details = db.execute(
            "SELECT details_json FROM results WHERE run_id = ? AND kind = 'prefix'",
            (str(result.run_id),),
        ).fetchone()[0]
    assert schema_version == 8
    assert json.loads(stored_details) == network_observation_details(network_observations)


@pytest.mark.asyncio
async def test_loading_prefix_details_with_vhost_provenance_fails_closed(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    collected_at = datetime(2026, 8, 11, 12, 1, tzinfo=UTC)
    result = CompletedResult.finish(
        target='example.com',
        started_at=collected_at,
        completed_at=collected_at,
        groups={'asn': ['AS64500']},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='routeviews',
                    status='completed',
                    duration_ms=1,
                    groups={'prefix': ['198.51.100.0/24']},
                ),
            )
        ),
        network_observations=(PrefixOriginObservation('routeviews', '198.51.100.0/24', 'AS64500', collected_at),),
    )
    await store.save_run(result)
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE executions SET name = 'vhost' WHERE run_id = ? AND name = 'routeviews'",
            (str(result.run_id),),
        )
        db.commit()

    with pytest.raises(ResultStoreError, match=r'Persisted virtual-host details are missing: 198\.51\.100\.0/24'):
        await store.load_run(result.run_id)


@pytest.mark.asyncio
async def test_schema_v7_migrates_vhost_collision_without_losing_references(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('750ab571-778d-490e-b760-70394d936eb4')
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V7_EVIDENCE_STATUS)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (str(run_id), 'example.com', '2026-08-09T12:00:00+00:00', '2026-08-09T12:01:00+00:00'),
        )
        db.execute(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            (str(run_id), 0, 'hostname', 'admin.example.com'),
        )
        db.execute(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            (str(run_id), 1, 'vhost', 'admin.example.com'),
        )
        db.execute(
            'INSERT INTO executions '
            '(run_id, position, producer_kind, name, status, duration_ms, result_count) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (str(run_id), 0, 'action', 'vhost', 'completed', 1.0, 2),
        )
        db.executemany(
            'INSERT INTO result_origins (run_id, result_position, execution_position) VALUES (?, ?, ?)',
            [(str(run_id), position, 0) for position in (0, 1)],
        )
        db.execute(
            'INSERT INTO artifacts '
            '(run_id, position, result_position, execution_position, kind, path, media_type, size_bytes, sha256, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                str(run_id),
                0,
                1,
                0,
                'screenshot',
                'screenshots/admin.example.com.png',
                'image/png',
                3,
                '0' * 64,
                '2026-08-09T12:01:00+00:00',
            ),
        )

    store = ResultStore(database)
    await store.initialize()
    await store.dispose()
    store = ResultStore(database)
    await store.initialize()

    with pytest.raises(ResultStoreError, match='virtual-host details'):
        await store.load_run(run_id)
    with sqlite3.connect(database) as db:
        result_columns = [row[1] for row in db.execute('PRAGMA table_info(results)')]
        stored = db.execute('SELECT kind, value, details_json FROM results').fetchall()
        execution = db.execute('SELECT name, result_count FROM executions').fetchone()
        origins = db.execute('SELECT result_position, execution_position FROM result_origins').fetchall()
        artifacts = db.execute('SELECT result_position, execution_position, path FROM artifacts').fetchall()
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert result_columns == ['run_id', 'position', 'kind', 'value', 'details_json']
    assert stored == [('hostname', 'admin.example.com', None)]
    assert execution == ('vhost', 1)
    assert origins == [(0, 0)]
    assert artifacts == [(0, 0, 'screenshots/admin.example.com.png')]
    assert schema_version == 8


@pytest.mark.asyncio
async def test_schema_v7_migrates_unstructured_vhost_without_action_origin_to_hostname(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('20f4b762-e9cb-4e10-96c6-85f982af50b3')
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V7_EVIDENCE_STATUS)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (str(run_id), 'example.com', '2026-08-09T12:00:00+00:00', '2026-08-09T12:01:00+00:00'),
        )
        db.execute(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            (str(run_id), 0, 'vhost', 'admin.example.com'),
        )

    store = ResultStore(database)
    await store.initialize()

    loaded = await store.load_run(run_id)

    assert loaded.results == (('hostname', 'admin.example.com'),)
    assert loaded.virtual_hosts == ()


@pytest.mark.asyncio
@pytest.mark.parametrize('details_json', [None, 'not-json', '[]', '[{"endpoint":"http://192.0.2.10:80/"}]'])
async def test_loading_malformed_vhost_details_fails_closed(tmp_path, details_json: str | None) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    result = CompletedResult.finish(
        target='example.com',
        started_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 9, 12, 1, tzinfo=UTC),
        groups={},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='vhost',
                    status='completed',
                    duration_ms=1,
                    groups={'hostname': ['admin.example.com']},
                ),
            )
        ),
        virtual_hosts=(vhost_observation('http://192.0.2.10', status=200, control_status=404),),
    )
    await store.save_run(result)
    with sqlite3.connect(database) as db:
        db.execute(
            'UPDATE results SET details_json = ? WHERE run_id = ?',
            (details_json, str(result.run_id)),
        )
        db.commit()

    with pytest.raises(ResultStoreError, match='virtual-host details'):
        await store.load_run(result.run_id)


@pytest.mark.asyncio
async def test_loading_vhost_details_without_vhost_provenance_preserves_compatibility_error(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    result = CompletedResult.finish(
        target='example.com',
        started_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 9, 12, 1, tzinfo=UTC),
        groups={},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='vhost',
                    status='completed',
                    duration_ms=1,
                    groups={'hostname': ['admin.example.com']},
                ),
            )
        ),
        virtual_hosts=(vhost_observation('http://192.0.2.10', status=200, control_status=404),),
    )
    await store.save_run(result)
    with sqlite3.connect(database) as db:
        db.execute('DELETE FROM result_origins WHERE run_id = ?', (str(result.run_id),))
        db.commit()

    with pytest.raises(
        ResultStoreError,
        match='Persisted virtual-host details require hostname results with vhost provenance',
    ):
        await store.load_run(result.run_id)


@pytest.mark.asyncio
async def test_loading_oversized_network_details_fails_before_json_decode(tmp_path, monkeypatch) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    collected_at = datetime(2026, 8, 11, 12, 1, tzinfo=UTC)
    result = CompletedResult.finish(
        target='example.com',
        started_at=datetime(2026, 8, 11, 12, 0, tzinfo=UTC),
        completed_at=collected_at,
        groups={'asn': ['AS64500']},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='routeviews',
                    status='completed',
                    duration_ms=1,
                    groups={'prefix': ['192.0.2.0/24']},
                ),
            )
        ),
        network_observations=(PrefixOriginObservation('routeviews', '192.0.2.0/24', 'AS64500', collected_at),),
    )
    await store.save_run(result)
    with sqlite3.connect(database) as db:
        db.execute(
            'UPDATE results SET details_json = ? WHERE run_id = ? AND kind = ?',
            ('[]', str(result.run_id), 'prefix'),
        )
        db.commit()
    monkeypatch.setattr('theHarvester.lib.network_evidence.MAX_NETWORK_DETAILS_BYTES', 1)

    with pytest.raises(ResultStoreError, match='Persisted network details are invalid'):
        await store.load_run(result.run_id)


@pytest.mark.asyncio
@pytest.mark.parametrize('evidence_status', ['partial', 'failed'])
async def test_sparse_evidence_status_survives_result_store_round_trip(tmp_path, evidence_status: str) -> None:
    store = ResultStore(tmp_path / 'stash.sqlite')
    await store.initialize()
    result = CompletedResult.finish(
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={},
        evidence_status=evidence_status,
    )

    await store.save_run(result)

    loaded = await store.load_run(result.run_id)
    assert loaded == result
    assert loaded.status == evidence_status


@pytest.mark.asyncio
async def test_completed_result_round_trip_preserves_source_provenance(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    result = CompletedResult.finish(
        run_id=UUID('9c024fb7-4877-4f6e-89ef-0bf6af59ade0'),
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={'hostname': ['api.example.com', 'mail.example.com']},
        observations=(
            ResultObservation('crtsh', 'hostname', 'api.example.com'),
            ResultObservation('certspotter', 'hostname', 'api.example.com'),
            ResultObservation('crtsh', 'hostname', 'mail.example.com'),
        ),
        source_executions=(
            SourceExecution('crtsh', 'completed', 12.5, 2),
            SourceExecution('certspotter', 'completed', 8.0, 1),
        ),
    )

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    with sqlite3.connect(database) as db:
        observations = db.execute(
            'SELECT o.run_id, e.name, r.kind, r.value '
            'FROM result_origins AS o '
            'JOIN executions AS e ON e.run_id = o.run_id AND e.position = o.execution_position '
            'JOIN results AS r ON r.run_id = o.run_id AND r.position = o.result_position '
            'ORDER BY e.name, r.value'
        ).fetchall()
        executions = db.execute(
            'SELECT run_id, producer_kind, name, status, result_count FROM executions ORDER BY position'
        ).fetchall()
    assert observations == [
        (str(result.run_id), 'certspotter', 'hostname', 'api.example.com'),
        (str(result.run_id), 'crtsh', 'hostname', 'api.example.com'),
        (str(result.run_id), 'crtsh', 'hostname', 'mail.example.com'),
    ]
    assert executions == [
        (str(result.run_id), 'source', 'crtsh', 'completed', 2),
        (str(result.run_id), 'source', 'certspotter', 'completed', 1),
    ]


@pytest.mark.asyncio
async def test_mixed_source_action_artifact_round_trip_uses_unified_tables(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    completed_at = datetime(2026, 8, 9, 12, 1, tzinfo=UTC)
    result = CompletedResult.finish(
        run_id=UUID('d721f4c5-1c76-4e7a-904a-23c5d6755834'),
        target='example.com',
        started_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        completed_at=completed_at,
        groups={'hostname': ['api.example.com']},
        source_executions=(SourceExecution('shared-name', 'completed', 2.0, 1),),
        observations=(ResultObservation('shared-name', 'hostname', 'api.example.com'),),
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='shared-name',
                    status='completed',
                    duration_ms=3.0,
                    groups={'ip': ['192.0.2.10']},
                ),
                screenshot_execution(completed_at),
                ActionExecution.finish(
                    action='takeover',
                    status='completed',
                    duration_ms=1.0,
                    groups={},
                ),
            )
        ),
    )

    await store.save_run(result)

    assert await store.load_run(result.run_id) == result
    assert [item.to_dict() for item in await store.action_yields(result.run_id)] == [
        {
            'action': 'screenshot',
            'observed_result_count': 0,
            'unique_result_count': 0,
            'shared_result_count': 0,
        },
        {
            'action': 'shared-name',
            'observed_result_count': 1,
            'unique_result_count': 1,
            'shared_result_count': 0,
        },
        {
            'action': 'takeover',
            'observed_result_count': 0,
            'unique_result_count': 0,
            'shared_result_count': 0,
        },
    ]
    with sqlite3.connect(database) as db:
        tables = {
            row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        }
        executions = db.execute('SELECT position, producer_kind, name, result_count FROM executions ORDER BY position').fetchall()
        origins = db.execute(
            'SELECT e.producer_kind, e.name, r.kind, r.value '
            'FROM result_origins AS o '
            'JOIN executions AS e ON e.run_id = o.run_id AND e.position = o.execution_position '
            'JOIN results AS r ON r.run_id = o.run_id AND r.position = o.result_position '
            'ORDER BY e.producer_kind, e.name'
        ).fetchall()
        artifacts = db.execute(
            'SELECT e.name, r.kind, r.value, a.kind, a.path, a.media_type, a.size_bytes, a.sha256, a.created_at '
            'FROM artifacts AS a '
            'JOIN executions AS e ON e.run_id = a.run_id AND e.position = a.execution_position '
            'JOIN results AS r ON r.run_id = a.run_id AND r.position = a.result_position'
        ).fetchall()
    assert tables == {
        'runs',
        'executions',
        'results',
        'result_origins',
        'artifacts',
        'legacy_observations',
        'run_records',
        'run_worker_leases',
    }
    assert executions == [
        (0, 'source', 'shared-name', 1),
        (1, 'action', 'shared-name', 1),
        (2, 'action', 'screenshot', 0),
        (3, 'action', 'takeover', 0),
    ]
    assert origins == [
        ('action', 'shared-name', 'ip', '192.0.2.10'),
        ('source', 'shared-name', 'hostname', 'api.example.com'),
    ]
    assert artifacts == [
        (
            'screenshot',
            'hostname',
            'api.example.com',
            'screenshot',
            'screenshots/api.example.com.png',
            'image/png',
            3,
            '0' * 64,
            completed_at.isoformat(),
        )
    ]

    with sqlite3.connect(database) as db:
        db.execute('PRAGMA foreign_keys = ON')
        db.execute('DELETE FROM runs WHERE run_id = ?', (str(result.run_id),))
        db.commit()
        assert db.execute('SELECT COUNT(*) FROM executions').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM results').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM result_origins').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0] == 0


@pytest.mark.asyncio
async def test_source_yields_distinguish_unique_and_shared_results(tmp_path) -> None:
    store = ResultStore(tmp_path / 'stash.sqlite')
    await store.initialize()
    result = CompletedResult.finish(
        run_id=UUID('bb2e9a76-f7fc-4eec-acbc-6da55a389d88'),
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={'hostname': ['api.example.com', 'mail.example.com', 'www.example.com']},
        observations=(
            ResultObservation('crtsh', 'hostname', 'api.example.com'),
            ResultObservation('certspotter', 'hostname', 'api.example.com'),
            ResultObservation('crtsh', 'hostname', 'mail.example.com'),
            ResultObservation('certspotter', 'hostname', 'www.example.com'),
        ),
        source_executions=(
            SourceExecution('crtsh', 'completed', 12.5, 2),
            SourceExecution('certspotter', 'completed', 8.0, 2),
            SourceExecution('empty-source', 'completed', 5.0, 0),
        ),
    )
    await store.save_run(result)

    yields = await store.source_yields(result.run_id)

    assert [item.to_dict() for item in yields] == [
        {
            'source': 'certspotter',
            'observed_result_count': 2,
            'unique_result_count': 1,
            'shared_result_count': 1,
        },
        {
            'source': 'crtsh',
            'observed_result_count': 2,
            'unique_result_count': 1,
            'shared_result_count': 1,
        },
        {
            'source': 'empty-source',
            'observed_result_count': 0,
            'unique_result_count': 0,
            'shared_result_count': 0,
        },
    ]


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
        migrated = db.execute('SELECT resource, kind, source FROM legacy_observations').fetchall()
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
async def test_schema_v2_upgrades_to_v8_without_rewriting_existing_rows(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('251d4047-190b-4a4d-9c4e-9eed3f23c8c7')
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V2_RUN_PROVENANCE)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (
                str(run_id),
                'example.com',
                '2026-08-09T12:00:00+00:00',
                '2026-08-09T12:01:00+00:00',
            ),
        )
        db.execute(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            (str(run_id), 0, 'hostname', 'api.example.com'),
        )
        db.execute(
            'INSERT INTO executions '
            '(run_id, position, producer_kind, name, status, duration_ms, result_count) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (str(run_id), 0, 'source', 'crtsh', 'completed', 12.5, 1),
        )
        db.execute(
            'INSERT INTO result_origins (run_id, result_position, execution_position) VALUES (?, ?, ?)',
            (str(run_id), 0, 0),
        )

    store = ResultStore(database)
    await store.initialize()
    await store.initialize()

    loaded = await store.load_run(run_id)
    assert loaded == CompletedResult.finish(
        run_id=run_id,
        target='example.com',
        started_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 9, 12, 1, tzinfo=UTC),
        groups={'hostname': ['api.example.com']},
        source_executions=(SourceExecution('crtsh', 'completed', 12.5, 1),),
        observations=(ResultObservation('crtsh', 'hostname', 'api.example.com'),),
    )
    with sqlite3.connect(database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0] == 0


@pytest.mark.asyncio
async def test_schema_v6_adds_nullable_evidence_status_without_rewriting_execution_status(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('cb34987b-9dd5-44f5-a58a-7ca7d34b0743')
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V6_RESULT_KINDS)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (
                str(run_id),
                'example.com',
                '2026-08-09T12:00:00+00:00',
                '2026-08-09T12:01:00+00:00',
            ),
        )
        db.execute(
            'INSERT INTO executions '
            '(run_id, position, producer_kind, name, status, duration_ms, result_count) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (str(run_id), 0, 'source', 'crtsh', 'partial', 12.5, 0),
        )

    store = ResultStore(database)
    await store.initialize()

    loaded = await store.load_run(run_id)
    with sqlite3.connect(database) as db:
        run_columns = {row[1] for row in db.execute('PRAGMA table_info(runs)')}
        stored_status = db.execute('SELECT evidence_status FROM runs WHERE run_id = ?', (str(run_id),)).fetchone()[0]
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert loaded.status == 'partial'
    assert stored_status is None
    assert 'evidence_status' in run_columns
    assert schema_version == 8


@pytest.mark.asyncio
async def test_schema_v4_merges_deprecated_url_kinds_without_losing_origins(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('d299651b-21c1-4511-8cac-63ba70f926f4')
    target_url = 'https://portal.example.com/login'
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V4_URL_KINDS)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (str(run_id), 'example.com', '2026-08-09T12:00:00+00:00', '2026-08-09T12:01:00+00:00'),
        )
        db.executemany(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            [
                (str(run_id), 0, 'api-endpoint', target_url),
                (str(run_id), 1, 'hostname', 'portal.example.com'),
                (str(run_id), 2, 'interesting-url', target_url),
                (str(run_id), 3, 'linkedin-link', target_url),
                (str(run_id), 4, 'url', target_url),
            ],
        )
        db.executemany(
            'INSERT INTO executions '
            '(run_id, position, producer_kind, name, status, duration_ms, result_count, error_type, stop_reason) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                (str(run_id), 0, 'source', 'builtwith', 'completed', 1.0, 1, None, None),
                (str(run_id), 1, 'source', 'rocketreach', 'completed', 1.0, 1, None, None),
                (str(run_id), 2, 'source', 'gitlab', 'completed', 1.0, 1, None, None),
                (str(run_id), 3, 'action', 'api-scan', 'completed', 1.0, 3, None, None),
                (str(run_id), 4, 'action', 'screenshot', 'completed', 1.0, 0, None, None),
            ],
        )
        db.executemany(
            'INSERT INTO result_origins (run_id, result_position, execution_position) VALUES (?, ?, ?)',
            [
                (str(run_id), 2, 0),
                (str(run_id), 3, 1),
                (str(run_id), 4, 2),
                (str(run_id), 0, 3),
                (str(run_id), 2, 3),
                (str(run_id), 4, 3),
            ],
        )
        db.execute(
            'INSERT INTO artifacts '
            '(run_id, position, result_position, execution_position, kind, path, media_type, size_bytes, sha256, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                str(run_id),
                0,
                2,
                4,
                'screenshot',
                'screenshots/portal.png',
                'image/png',
                3,
                '0' * 64,
                '2026-08-09T12:01:00+00:00',
            ),
        )
        db.executemany(
            'INSERT INTO legacy_observations (domain, resource, kind, discovered_on, source) VALUES (?, ?, ?, ?, ?)',
            [
                ('example.com', target_url, 'interesting-url', '2026-08-09', 'builtwith'),
                ('example.com', target_url, 'linkedinlinks', '2026-08-09', 'rocketreach'),
            ],
        )

    store = ResultStore(database)
    await store.initialize()
    loaded = await store.load_run(run_id)

    assert loaded.results == (('hostname', 'portal.example.com'), ('url', target_url))
    assert {(item.source, item.kind, item.value) for item in loaded.observations} == {
        ('builtwith', 'url', target_url),
        ('gitlab', 'url', target_url),
        ('rocketreach', 'url', target_url),
    }
    api_scan = next(item for item in loaded.active_evidence.executions if item.action == 'api-scan')
    assert api_scan.result_count == 1
    assert {(item.kind, item.value) for item in api_scan.observations} == {('url', target_url)}
    screenshot = next(item for item in loaded.active_evidence.executions if item.action == 'screenshot')
    assert screenshot.artifacts[0].subject_kind == 'url'
    assert screenshot.artifacts[0].subject_value == target_url
    with sqlite3.connect(database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert db.execute('SELECT DISTINCT kind FROM legacy_observations').fetchall() == [('url',)]
        assert db.execute('SELECT result_count FROM executions WHERE name = ?', ('api-scan',)).fetchone()[0] == 1


@pytest.mark.asyncio
async def test_schema_v5_merges_ip_address_into_ip_without_losing_provenance_or_artifacts(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    run_id = UUID('5b240ef2-e714-45de-b38f-174f20447f8b')
    address = '192.0.2.1'
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V5_RESULT_KINDS)
        db.execute(
            'INSERT INTO runs (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
            (str(run_id), 'example.com', '2026-08-09T12:00:00+00:00', '2026-08-09T12:01:00+00:00'),
        )
        db.executemany(
            'INSERT INTO results (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
            [
                (str(run_id), 0, 'ip-address', address),
                (str(run_id), 1, 'ip', address),
            ],
        )
        db.executemany(
            'INSERT INTO executions '
            '(run_id, position, producer_kind, name, status, duration_ms, result_count, error_type, stop_reason) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                (str(run_id), 0, 'source', 'dns', 'completed', 1.0, 2, None, None),
                (str(run_id), 1, 'action', 'screenshot', 'completed', 2.0, 2, None, None),
            ],
        )
        db.executemany(
            'INSERT INTO result_origins (run_id, result_position, execution_position) VALUES (?, ?, ?)',
            [
                (str(run_id), 0, 0),
                (str(run_id), 1, 0),
                (str(run_id), 0, 1),
                (str(run_id), 1, 1),
            ],
        )
        db.execute(
            'INSERT INTO artifacts '
            '(run_id, position, result_position, execution_position, kind, path, media_type, size_bytes, sha256, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                str(run_id),
                0,
                0,
                1,
                'screenshot',
                'screenshots/192.0.2.1.png',
                'image/png',
                3,
                '0' * 64,
                '2026-08-09T12:01:00+00:00',
            ),
        )
        db.executemany(
            'INSERT INTO legacy_observations (domain, resource, kind, discovered_on, source) VALUES (?, ?, ?, ?, ?)',
            [
                ('example.com', address, 'ip-address', '2026-08-09', 'dns'),
                ('example.com', address, 'ip', '2026-08-09', 'dns'),
            ],
        )

    store = ResultStore(database)
    await store.initialize()
    loaded = await store.load_run(run_id)

    assert loaded.results == (('ip', address),)
    assert [(item.source, item.kind, item.value) for item in loaded.observations] == [('dns', 'ip', address)]
    assert loaded.source_executions[0].result_count == 1
    screenshot = loaded.active_evidence.executions[0]
    assert [(item.kind, item.value) for item in screenshot.observations] == [('ip', address)]
    assert screenshot.artifacts[0].subject_kind == 'ip'
    assert screenshot.artifacts[0].subject_value == address
    with sqlite3.connect(database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert db.execute('SELECT kind, value FROM results').fetchall() == [('ip', address)]
        assert db.execute('SELECT execution_position FROM result_origins ORDER BY execution_position').fetchall() == [
            (0,),
            (1,),
        ]
        assert db.execute('SELECT result_count FROM executions ORDER BY position').fetchall() == [(1,), (1,)]
        assert db.execute('SELECT DISTINCT kind FROM legacy_observations').fetchall() == [('ip',)]


@pytest.mark.asyncio
async def test_released_results_migrate_to_legacy_observations(tmp_path) -> None:
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
        observations = db.execute('SELECT resource, kind FROM legacy_observations ORDER BY id').fetchall()
        result_columns = [row[1] for row in db.execute('PRAGMA table_info(results)')]
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert 'legacy_results' not in tables
    assert result_columns == ['run_id', 'position', 'kind', 'value', 'details_json']
    assert observations == [
        ('api.example.com', 'hostname'),
        ('192.0.2.1', 'ip'),
        ('Ada Lovelace', 'person'),
        ('https://linkedin.test/ada', 'url'),
        ('https://admin.example.com', 'url'),
        ('AS64496', 'asn'),
        ('/api/v1', 'url'),
        ('admin@example.com', 'email'),
    ]
    assert schema_version == 8


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
        migrated = db.execute('SELECT domain, resource, kind, discovered_on, source FROM legacy_observations').fetchall()
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
        rows = db.execute('SELECT domain, resource, kind, source FROM legacy_observations').fetchall()
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

    artifact_run_id = UUID('7ff120b6-4aec-4d27-b2db-d3ac9fd87340')
    completed_at = datetime(2026, 8, 9, 12, 1, tzinfo=UTC)
    failing_artifact = CompletedResult.finish(
        run_id=artifact_run_id,
        target='example.com',
        started_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        completed_at=completed_at,
        groups={'hostname': ['api.example.com']},
        active_evidence=ActiveEvidence(executions=(screenshot_execution(completed_at),)),
    )
    with sqlite3.connect(database) as db:
        db.execute(
            f"""
            CREATE TRIGGER fail_artifact
            BEFORE INSERT ON artifacts
            WHEN NEW.run_id = '{artifact_run_id}'
            BEGIN
                SELECT RAISE(ABORT, 'forced artifact failure');
            END
            """
        )

    with pytest.raises(ResultStoreError, match='Could not save enumeration run'):
        await store.save_run(failing_artifact)

    with sqlite3.connect(database) as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0] == 0


@pytest.mark.asyncio
async def test_legacy_observations_keep_the_released_normalized_schema(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    await store.initialize()
    await store.record_observations('example.com', ['api.example.com', 'www.example.com'], 'hostname', 'crtsh')
    await store.record_observations('example.com', ['admin@example.com'], 'email', 'hunter')
    await store.record_observations('example.com', ['192.0.2.1'], 'ip', 'dns')
    await store.record_observations('example.com', ['{"firstname":"Ada","lastname":"Lovelace"}'], 'person', 'hunter')
    await store.record_observations('example.com', ['vhost.example.com'], 'hostname', 'virtual-host')
    await store.record_observations('example.com', ['443'], 'shodan', 'shodan')

    with sqlite3.connect(database) as db:
        columns = [row[1] for row in db.execute('PRAGMA table_info(legacy_observations)')]
        rows = db.execute('SELECT domain, resource, kind, source FROM legacy_observations ORDER BY id').fetchall()

    assert columns == ['id', 'domain', 'resource', 'kind', 'discovered_on', 'source']
    assert rows == [
        ('example.com', 'api.example.com', 'hostname', 'crtsh'),
        ('example.com', 'www.example.com', 'hostname', 'crtsh'),
        ('example.com', 'admin@example.com', 'email', 'hunter'),
        ('example.com', '192.0.2.1', 'ip', 'dns'),
        ('example.com', '{"firstname":"Ada","lastname":"Lovelace"}', 'person', 'hunter'),
        ('example.com', 'vhost.example.com', 'hostname', 'virtual-host'),
        ('example.com', '443', 'shodan', 'shodan'),
    ]


@pytest.mark.asyncio
async def test_schema_v1_observations_upgrade_without_losing_rows(tmp_path) -> None:
    database = tmp_path / 'stash.sqlite'
    store = ResultStore(database)
    with sqlite3.connect(database) as db:
        db.executescript(SCHEMA_V1_DISCOVERY_OBSERVATIONS)
        db.execute(
            'INSERT INTO discovery_observations (domain, resource, kind, discovered_on, source) VALUES (?, ?, ?, ?, ?)',
            ('example.com', 'api.example.com', 'hostname', '2026-08-08', 'crtsh'),
        )

    await store.initialize()

    with sqlite3.connect(database) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        rows = db.execute('SELECT domain, resource, kind, source FROM legacy_observations').fetchall()
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert 'discovery_observations' not in tables
    assert rows == [('example.com', 'api.example.com', 'hostname', 'crtsh')]
    assert schema_version == 8


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
