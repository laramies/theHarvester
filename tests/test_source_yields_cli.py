import asyncio
import json
import sqlite3
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from theHarvester import source_yields
from theHarvester.lib import database as database_module
from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution
from theHarvester.lib.database import ResultStore
from theHarvester.lib.evidence_types import RESULT_KINDS

RUN_ONE = UUID('11111111-1111-4111-8111-111111111111')
RUN_TWO = UUID('22222222-2222-4222-8222-222222222222')


def test_project_installs_harvest_yields_command() -> None:
    project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))

    assert project['project']['scripts']['harvest-yields'] == 'theHarvester.source_yields:main'


def _completed_run(
    run_id: UUID,
    *,
    target: str = 'example.test',
    observations: tuple[ResultObservation, ...],
    resolved_hostnames: tuple[str, ...] = (),
) -> CompletedResult:
    started_at = datetime(2026, 8, 23, 12, tzinfo=UTC) + timedelta(minutes=int(str(run_id)[0]))
    sources = sorted({observation.source for observation in observations})
    active_evidence = (
        ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='dns-resolve',
                    status='completed',
                    duration_ms=1,
                    groups={'hostname': resolved_hostnames},
                ),
            )
        )
        if resolved_hostnames
        else ActiveEvidence()
    )
    return CompletedResult.finish(
        run_id=run_id,
        target=target,
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=1),
        groups={
            observation.kind: [item.value for item in observations if item.kind == observation.kind]
            for observation in observations
        },
        source_executions=tuple(
            SourceExecution(
                source=source,
                status='completed',
                duration_ms=1,
                result_count=sum(observation.source == source for observation in observations),
            )
            for source in sources
        ),
        observations=observations,
        active_evidence=active_evidence,
    )


async def _create_database(database: Path) -> None:
    store = ResultStore(database)
    await store.initialize()
    await store.save_run(
        _completed_run(
            RUN_ONE,
            observations=(
                ResultObservation('alpha', 'hostname', 'shared.example.test'),
                ResultObservation('alpha', 'hostname', 'unique-alpha.example.test'),
                ResultObservation('beta', 'hostname', 'shared.example.test'),
                ResultObservation('beta', 'hostname', 'unique-beta.example.test'),
            ),
            resolved_hostnames=('shared.example.test', 'unique-alpha.example.test'),
        )
    )
    await store.save_run(
        _completed_run(
            RUN_TWO,
            observations=(
                ResultObservation('alpha', 'hostname', 'second-shared.example.test'),
                ResultObservation('beta', 'hostname', 'second-shared.example.test'),
                ResultObservation('gamma', 'hostname', 'second-gamma.example.test'),
                ResultObservation('alpha', 'ip', '192.0.2.1'),
                ResultObservation('beta', 'ip', '192.0.2.1'),
                ResultObservation('gamma', 'ip', '198.51.100.2'),
                ResultObservation('alpha', 'asn', 'AS64496'),
            ),
            resolved_hostnames=('second-shared.example.test',),
        )
    )
    await store.dispose()


async def _create_target_inventory_database(database: Path) -> None:
    store = ResultStore(database)
    await store.initialize()
    targets = (
        'EXAMPLE.TEST.',
        'example.test',
        'www.Example.test.',
        'bücher.example',
        'XN--BCHER-KVA.EXAMPLE.',
        '2001:0DB8:0:0::1',
        'as064496',
        '198.51.100.23/24',
        '  Example Company  ',
        'example company',
    )
    for index, target in enumerate(targets, start=3):
        await store.save_run(
            _completed_run(
                UUID(f'{index:08d}-0000-4000-8000-000000000000'),
                target=target,
                observations=(),
            )
        )
    await store.dispose()


def test_list_targets_table_canonicalizes_counts_and_sorts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_target_inventory_database(database))

    assert source_yields.main(['--database', str(database), '--list-targets']) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ['TARGET', 'RUNS']
    assert [line.rsplit(maxsplit=1) for line in lines[1:]] == [
        ['198.51.100.0/24', '1'],
        ['2001:db8::1', '1'],
        ['AS64496', '1'],
        ['Example Company', '1'],
        ['example company', '1'],
        ['example.test', '2'],
        ['www.example.test', '1'],
        ['xn--bcher-kva.example', '2'],
    ]


def test_list_targets_json_preserves_stored_targets_and_schema_version(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_target_inventory_database(database))
    with sqlite3.connect(database) as connection:
        stored_targets = connection.execute('SELECT target FROM runs ORDER BY run_id').fetchall()
        connection.execute('PRAGMA user_version = 7')

    assert source_yields.main(['--database', str(database), '--list-targets', '--format', 'json']) == 0

    output = capsys.readouterr().out
    assert output.endswith('\n')
    assert json.loads(output) == {
        'targets': [
            {'target': '198.51.100.0/24', 'run_count': 1},
            {'target': '2001:db8::1', 'run_count': 1},
            {'target': 'AS64496', 'run_count': 1},
            {'target': 'Example Company', 'run_count': 1},
            {'target': 'example company', 'run_count': 1},
            {'target': 'example.test', 'run_count': 2},
            {'target': 'www.example.test', 'run_count': 1},
            {'target': 'xn--bcher-kva.example', 'run_count': 2},
        ]
    }
    with sqlite3.connect(database) as connection:
        assert connection.execute('PRAGMA user_version').fetchone() == (7,)
        assert connection.execute('SELECT target FROM runs ORDER BY run_id').fetchall() == stored_targets


def test_list_targets_empty_database_succeeds(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    store = ResultStore(database)
    asyncio.run(store.initialize())
    asyncio.run(store.dispose())

    assert source_yields.main(['--database', str(database), '--list-targets']) == 0
    assert capsys.readouterr().out == 'TARGET  RUNS\n'
    assert source_yields.main(['--database', str(database), '--list-targets', '--format', 'json']) == 0
    assert capsys.readouterr().out == '{"targets": []}\n'


def test_list_targets_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), '--list-targets', '--run-id', str(RUN_ONE)])

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_missing_database_fails_without_creating_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'missing.sqlite'

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database)])

    assert error.value.code == 2
    assert 'database does not exist' in capsys.readouterr().err
    assert not database.exists()


def test_default_database_uses_the_standard_result_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'stash.sqlite'
    asyncio.run(_create_database(database))
    monkeypatch.setattr(database_module, '_DEFAULT_DATABASE', database)

    assert source_yields.main([]) == 0

    assert capsys.readouterr().out.startswith('Kind: hostname\nRun count: 2\n')


def test_default_table_ranks_by_unique_per_run_and_aligns_columns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database)]) == 0

    assert capsys.readouterr().out.splitlines() == [
        'Kind: hostname',
        'Run count: 2',
        'SOURCE  RUNS  OBSERVED  UNIQUE  UNIQUE/RUN  SHARED  RESOLVED  UNIQUE-RESOLVED  UNIQUE-RESOLVED/RUN',
        'gamma   1     1         1       1.00        0       0         0                0.00',
        'alpha   2     3         1       0.50        2       3         1                0.50',
        'beta    2     3         1       0.50        2       2         0                0.00',
    ]


@pytest.mark.parametrize('kind', sorted(RESULT_KINDS))
def test_kind_accepts_every_result_kind_and_only_hostname_shows_resolution_columns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database), '--kind', kind]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == f'Kind: {kind}'
    assert ('RESOLVED' in lines[2]) is (kind == 'hostname')
    if kind == 'ip':
        assert [line.split() for line in lines[3:]] == [
            ['gamma', '1', '1', '1', '1.00', '0'],
            ['alpha', '2', '1', '0', '0.00', '1'],
            ['beta', '2', '1', '0', '0.00', '1'],
        ]


def test_run_id_selects_one_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database), '--run-id', str(RUN_ONE)]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == 'Run count: 1'
    assert [line.split() for line in lines[3:]] == [
        ['alpha', '1', '2', '1', '1.00', '1', '2', '1', '1.00'],
        ['beta', '1', '2', '1', '1.00', '1', '1', '0', '0.00'],
    ]


def test_unknown_run_id_fails_instead_of_reporting_an_empty_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))
    missing_run = UUID('33333333-3333-4333-8333-333333333333')

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), '--run-id', str(missing_run)])

    assert error.value.code == 2
    assert 'completed result not found' in capsys.readouterr().err


@pytest.mark.parametrize('kind', ['hostname', 'ip'])
def test_json_format_is_machine_readable_and_uses_kind_specific_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database), '--kind', kind, '--format', 'json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['kind'] == kind
    assert payload['run_count'] == 2
    assert [row['source'] for row in payload['source_yields']] == ['gamma', 'alpha', 'beta']
    resolution_fields = {
        'resolved_hostname_count',
        'unique_resolved_hostname_count',
        'unique_resolved_hostname_count_per_run',
    }
    assert all(resolution_fields <= row.keys() for row in payload['source_yields']) is (kind == 'hostname')
    assert {row['source']: row['run_count'] for row in payload['source_yields']} == {'alpha': 2, 'beta': 2, 'gamma': 1}
    assert {row['source']: row['unique_result_count_per_run'] for row in payload['source_yields']} == (
        {'alpha': 0.5, 'beta': 0.5, 'gamma': 1.0} if kind == 'hostname' else {'alpha': 0.0, 'beta': 0.0, 'gamma': 1.0}
    )
