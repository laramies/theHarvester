import asyncio
import json
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from theHarvester import source_yields
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
        target='example.test',
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
                ResultObservation('alpha', 'hostname', 'second-alpha.example.test'),
                ResultObservation('beta', 'hostname', 'second-beta.example.test'),
                ResultObservation('gamma', 'hostname', 'second-gamma.example.test'),
                ResultObservation('alpha', 'ip', '192.0.2.1'),
                ResultObservation('beta', 'ip', '192.0.2.1'),
                ResultObservation('gamma', 'ip', '198.51.100.2'),
                ResultObservation('alpha', 'asn', 'AS64496'),
            ),
            resolved_hostnames=('second-beta.example.test',),
        )
    )
    await store.dispose()


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


def test_default_table_sums_per_run_hostname_yields_and_sorts_sources(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database)]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[:3] == [
        'Kind: hostname',
        'Run count: 2',
        'SOURCE  RUNS  OBSERVED  UNIQUE  SHARED  RESOLVED  UNIQUE-RESOLVED',
    ]
    assert [line.split() for line in lines[3:]] == [
        ['alpha', '2', '3', '2', '1', '2', '1'],
        ['beta', '2', '3', '2', '1', '2', '1'],
        ['gamma', '1', '1', '1', '0', '0', '0'],
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
            ['gamma', '1', '1', '1', '0'],
            ['alpha', '2', '1', '0', '1'],
            ['beta', '2', '1', '0', '1'],
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
        ['alpha', '1', '2', '1', '1', '2', '1'],
        ['beta', '1', '2', '1', '1', '1', '0'],
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
    assert [row['source'] for row in payload['source_yields']] == (
        ['alpha', 'beta', 'gamma'] if kind == 'hostname' else ['gamma', 'alpha', 'beta']
    )
    resolution_fields = {'resolved_hostname_count', 'unique_resolved_hostname_count'}
    assert all(resolution_fields <= row.keys() for row in payload['source_yields']) is (kind == 'hostname')
    assert {row['source']: row['run_count'] for row in payload['source_yields']} == {'alpha': 2, 'beta': 2, 'gamma': 1}
