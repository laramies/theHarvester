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
from theHarvester.lib.evidence_types import RESULT_KINDS, ExecutionStatus

RUN_ONE = UUID('11111111-1111-4111-8111-111111111111')
RUN_TIE_LATER = UUID('11111111-1111-4111-8111-111111111112')
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
    source_statuses: dict[str, tuple[ExecutionStatus, str | None, str | None]] | None = None,
    dns_status: ExecutionStatus | None = None,
    addressability: dict[str, str] | None = None,
) -> CompletedResult:
    started_at = datetime(2026, 8, 23, 12, tzinfo=UTC) + timedelta(minutes=int(str(run_id)[0]))
    source_statuses = source_statuses or {}
    sources = sorted({observation.source for observation in observations} | set(source_statuses))
    action_executions = []
    if dns_status is not None or resolved_hostnames:
        action_executions.append(
            ActionExecution.finish(
                action='dns-resolve',
                status=dns_status or 'completed',
                duration_ms=1,
                groups={'hostname': resolved_hostnames},
            )
        )
    if addressability:
        action_executions.append(
            ActionExecution.finish(
                action='dns-recursive',
                status='completed',
                duration_ms=1,
                groups={
                    'dns-recursive-classification': (
                        json.dumps(
                            {'addressability': classification, 'hostname': hostname},
                            separators=(',', ':'),
                            sort_keys=True,
                        )
                        for hostname, classification in addressability.items()
                    )
                },
            )
        )
    active_evidence = ActiveEvidence(executions=tuple(action_executions))
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
                status=source_statuses.get(source, ('completed', None, None))[0],
                duration_ms=1,
                result_count=sum(observation.source == source for observation in observations),
                error_type=source_statuses.get(source, ('completed', None, None))[1],
                stop_reason=source_statuses.get(source, ('completed', None, None))[2],
            )
            for source in sources
        ),
        observations=observations,
        active_evidence=active_evidence,
    )


async def _create_tracking_database(database: Path) -> None:
    store = ResultStore(database)
    await store.initialize()
    await store.save_run(
        _completed_run(
            RUN_ONE,
            target='EXAMPLE.TEST.',
            observations=(
                ResultObservation('alpha', 'hostname', 'missing.example.test'),
                ResultObservation('alpha', 'hostname', 'persist.example.test'),
                ResultObservation('beta', 'hostname', 'inconclusive.example.test'),
            ),
            resolved_hostnames=('missing.example.test',),
            source_statuses={'beta': ('partial', 'BaselineTimeout', 'baseline-errors')},
            dns_status='completed',
        )
    )
    await store.save_run(
        _completed_run(
            RUN_TWO,
            observations=(
                ResultObservation('alpha', 'hostname', 'persist.example.test'),
                ResultObservation('alpha', 'hostname', 'new.example.test'),
                ResultObservation('beta', 'hostname', 'uncertain-new.example.test'),
            ),
            resolved_hostnames=('new.example.test', 'persist.example.test'),
            source_statuses={'beta': ('partial', 'TimeoutError', 'request-errors')},
            dns_status='completed',
            addressability={'new.example.test': 'currently-addressable'},
        )
    )
    await store.dispose()


async def _create_unreliable_dns_tracking_database(database: Path) -> None:
    hostname = 'unchecked.example.test'
    store = ResultStore(database)
    await store.initialize()
    await store.save_run(
        _completed_run(
            RUN_ONE,
            observations=(ResultObservation('alpha', 'hostname', hostname),),
        )
    )
    await store.save_run(
        _completed_run(
            RUN_TWO,
            observations=(ResultObservation('alpha', 'hostname', hostname),),
            dns_status='failed',
        )
    )
    await store.dispose()


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


async def _create_multi_target_database(database: Path) -> None:
    store = ResultStore(database)
    await store.initialize()
    await store.save_run(
        _completed_run(
            RUN_ONE,
            target='EXAMPLE.TEST.',
            observations=(ResultObservation('alpha', 'hostname', 'alpha.example.test'),),
        )
    )
    await store.save_run(
        _completed_run(
            RUN_TWO,
            target='other.example',
            observations=(ResultObservation('alpha', 'hostname', 'alpha.other.example'),),
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


def test_target_selects_only_matching_canonical_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    assert source_yields.main(['--database', str(database), '--target', 'example.test', '--format', 'json']) == 0

    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 1,
        'source_yields': [
            {
                'observed_result_count': 1,
                'resolved_hostname_count': 0,
                'run_count': 1,
                'shared_result_count': 0,
                'source': 'alpha',
                'unique_resolved_hostname_count': 0,
                'unique_resolved_hostname_count_per_run': 0.0,
                'unique_result_count': 1,
                'unique_result_count_per_run': 1.0,
            }
        ],
        'target': 'example.test',
    }


@pytest.mark.parametrize(
    ('requested', 'canonical', 'run_count'),
    [
        ('EXAMPLE.TEST.', 'example.test', 2),
        ('BÜCHER.EXAMPLE.', 'xn--bcher-kva.example', 2),
        ('2001:0db8::1', '2001:db8::1', 1),
        ('AS064496', 'AS64496', 1),
        ('198.51.100.23/24', '198.51.100.0/24', 1),
        ('  Example Company  ', 'Example Company', 1),
    ],
)
def test_target_selection_uses_canonical_identity_without_aliasing_free_text(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    requested: str,
    canonical: str,
    run_count: int,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_target_inventory_database(database))

    assert source_yields.main(['--database', str(database), '--target', requested, '--format', 'json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['target'] == canonical
    assert payload['run_count'] == run_count


def test_unknown_target_fails_with_inventory_hint(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), '--target', 'missing.example'])

    assert error.value.code == 2
    assert 'target not found: missing.example; use --list-targets' in capsys.readouterr().err


def test_target_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), '--target', 'example.test', '--run-id', str(RUN_ONE)])

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_unscoped_report_refuses_to_mix_multiple_targets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database)])

    assert error.value.code == 2
    message = capsys.readouterr().err
    assert '2 canonical targets' in message
    assert '--list-targets' in message


def test_all_targets_explicitly_restores_mixed_target_json_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    assert source_yields.main(['--database', str(database), '--all-targets', '--format', 'json']) == 0

    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 2,
        'source_yields': [
            {
                'observed_result_count': 2,
                'resolved_hostname_count': 0,
                'run_count': 2,
                'shared_result_count': 0,
                'source': 'alpha',
                'unique_resolved_hostname_count': 0,
                'unique_resolved_hostname_count_per_run': 0.0,
                'unique_result_count': 2,
                'unique_result_count_per_run': 1.0,
            }
        ],
        'targets': [
            {'run_count': 1, 'target': 'example.test'},
            {'run_count': 1, 'target': 'other.example'},
        ],
    }


def test_all_targets_table_labels_scope_and_lists_every_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    assert source_yields.main(['--database', str(database), '--all-targets']) == 0

    assert capsys.readouterr().out.splitlines()[:7] == [
        'Scope: all targets',
        'TARGET         RUNS',
        'example.test   1',
        'other.example  1',
        'Kind: hostname',
        'Run count: 2',
        'SOURCE  RUNS  OBSERVED  UNIQUE  UNIQUE/RUN  SHARED  RESOLVED  UNIQUE-RESOLVED  UNIQUE-RESOLVED/RUN',
    ]


@pytest.mark.parametrize('conflicting', ['--list-targets', '--target'])
def test_all_targets_rejects_other_scope_selectors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    conflicting: str,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))
    args = ['--database', str(database), '--all-targets', conflicting]
    if conflicting == '--target':
        args.append('example.test')

    with pytest.raises(SystemExit) as error:
        source_yields.main(args)

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_all_targets_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), '--all-targets', '--run-id', str(RUN_ONE)])

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_run_changes_distinguish_missing_from_inconclusive_using_persisted_source_outcomes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    assert source_yields.main(['--database', str(database), '--run-id', str(RUN_TWO), '--changes', '--format', 'json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['target'] == 'example.test'
    assert payload['comparison_count'] == 1
    assert payload['comparisons'][0] == {
        'baseline_completed_at': '2026-08-23T12:01:01+00:00',
        'baseline_run_id': str(RUN_ONE),
        'completed_at': '2026-08-23T12:02:01+00:00',
        'counts': {'inconclusive': 2, 'missing': 1, 'new': 1, 'persisting': 1},
        'run_id': str(RUN_TWO),
        'source_cohort': ['alpha', 'beta'],
    }
    changes = {row['hostname']: row for row in payload['hostname_changes']}
    assert set(changes) == {
        'inconclusive.example.test',
        'missing.example.test',
        'new.example.test',
        'uncertain-new.example.test',
    }
    assert changes['new.example.test'] == {
        'baseline_run_id': str(RUN_ONE),
        'blocking_sources': [],
        'change': 'new',
        'current_addressability': 'currently-addressable',
        'current_dns_action_status': 'completed',
        'current_resolution_evidence': 'positive',
        'current_sources': ['alpha'],
        'hostname': 'new.example.test',
        'previous_addressability': None,
        'previous_dns_action_status': 'completed',
        'previous_resolution_evidence': 'not-checked',
        'previous_sources': [],
        'run_id': str(RUN_TWO),
        'source_exclusive': True,
    }
    assert changes['missing.example.test']['change'] == 'missing'
    assert changes['missing.example.test']['blocking_sources'] == []
    assert changes['missing.example.test']['previous_resolution_evidence'] == 'positive'
    assert changes['inconclusive.example.test']['change'] == 'inconclusive'
    assert changes['inconclusive.example.test']['blocking_sources'] == [
        {
            'error_type': 'TimeoutError',
            'source': 'beta',
            'status': 'partial',
            'stop_reason': 'request-errors',
        }
    ]
    assert changes['uncertain-new.example.test']['change'] == 'inconclusive'
    assert changes['uncertain-new.example.test']['current_sources'] == ['beta']
    assert changes['uncertain-new.example.test']['source_exclusive'] is True
    assert changes['uncertain-new.example.test']['blocking_sources'] == [
        {
            'error_type': 'BaselineTimeout',
            'source': 'beta',
            'status': 'partial',
            'stop_reason': 'baseline-errors',
        }
    ]


def test_target_changes_reports_every_run_pair_and_a_clear_null_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    assert source_yields.main(['--database', str(database), '--target', 'example.test', '--changes', '--format', 'json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['comparison_count'] == 2
    assert payload['comparisons'][0] == {
        'baseline_completed_at': None,
        'baseline_run_id': None,
        'completed_at': '2026-08-23T12:01:01+00:00',
        'counts': {'inconclusive': 0, 'missing': 0, 'new': 0, 'persisting': 0},
        'message': 'No previous finalized run has the same source cohort.',
        'run_id': str(RUN_ONE),
        'source_cohort': ['alpha', 'beta'],
    }
    assert payload['comparisons'][1]['baseline_run_id'] == str(RUN_ONE)
    assert {row['run_id'] for row in payload['hostname_changes']} == {str(RUN_TWO)}


def test_run_id_breaks_an_equal_completion_time_tie_deterministically(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    store = ResultStore(database)
    asyncio.run(store.initialize())
    asyncio.run(
        store.save_run(
            _completed_run(
                RUN_TIE_LATER,
                observations=(ResultObservation('alpha', 'hostname', 'later.example.test'),),
            )
        )
    )
    asyncio.run(
        store.save_run(
            _completed_run(
                RUN_ONE,
                observations=(ResultObservation('alpha', 'hostname', 'earlier.example.test'),),
            )
        )
    )
    asyncio.run(store.dispose())

    assert (
        source_yields.main(
            ['--database', str(database), '--run-id', str(RUN_TIE_LATER), '--changes', '--format', 'json']
        )
        == 0
    )

    comparison = json.loads(capsys.readouterr().out)['comparisons'][0]
    assert comparison['baseline_run_id'] == str(RUN_ONE)


def test_include_persisting_adds_unchanged_hostname_rows_without_changing_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    assert (
        source_yields.main(
            [
                '--database',
                str(database),
                '--run-id',
                str(RUN_TWO),
                '--changes',
                '--include-persisting',
                '--format',
                'json',
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    persisting = [row for row in payload['hostname_changes'] if row['change'] == 'persisting']
    assert [(row['hostname'], row['source_exclusive']) for row in persisting] == [('persist.example.test', True)]
    assert payload['comparisons'][0]['counts']['persisting'] == 1


def test_failed_dns_action_does_not_claim_a_sourced_hostname_was_checked(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_unreliable_dns_tracking_database(database))

    assert (
        source_yields.main(
            [
                '--database',
                str(database),
                '--run-id',
                str(RUN_TWO),
                '--changes',
                '--include-persisting',
                '--format',
                'json',
            ]
        )
        == 0
    )

    row = json.loads(capsys.readouterr().out)['hostname_changes'][0]
    assert row['current_dns_action_status'] == 'failed'
    assert row['current_resolution_evidence'] == 'not-checked'


def test_changes_table_is_human_readable_and_explains_inconclusive_rows(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    assert source_yields.main(['--database', str(database), '--run-id', str(RUN_TWO), '--changes']) == 0

    output = capsys.readouterr().out
    assert output.startswith('Target: example.test\nComparison count: 1\n')
    assert 'NEW  PERSISTING  MISSING  INCONCLUSIVE' in output
    lines = output.splitlines()
    assert lines[4].split() == [
        'CHANGE',
        'HOSTNAME',
        'SOURCES',
        'EXCLUSIVE',
        'RESOLUTION',
        'ADDRESSABILITY',
        'BLOCKING',
        'SOURCES',
    ]
    assert [line.split()[:2] for line in lines[5:]] == [
        ['NEW', 'new.example.test'],
        ['MISSING', 'missing.example.test'],
        ['INCONCLUSIVE', 'inconclusive.example.test'],
        ['INCONCLUSIVE', 'uncertain-new.example.test'],
    ]
    assert 'beta:partial:TimeoutError:request-errors' in output
    assert 'beta:partial:BaselineTimeout:baseline-errors' in output


def test_changes_table_explains_when_a_run_has_no_comparable_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    assert source_yields.main(['--database', str(database), '--run-id', str(RUN_ONE), '--changes']) == 0

    output = capsys.readouterr().out
    assert f'{RUN_ONE}: No previous finalized run has the same source cohort.' in output


@pytest.mark.parametrize(
    'args',
    [
        ['--include-persisting'],
        ['--changes', '--kind', 'ip'],
        ['--changes', '--all-targets'],
        ['--changes', '--list-targets'],
    ],
)
def test_changes_rejects_ambiguous_or_non_hostname_arguments(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_tracking_database(database))

    with pytest.raises(SystemExit) as error:
        source_yields.main(['--database', str(database), *args])

    assert error.value.code == 2
    assert capsys.readouterr().err


def test_help_makes_persisted_read_only_change_modes_obvious(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        source_yields.main(['--help'])

    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert 'never runs discovery or DNS' in help_text
    assert 'harvest-yields --target example.test --changes' in help_text
    assert 'harvest-yields --run-id RUN_ID --changes' in help_text
    assert '--include-persisting' in help_text


def test_unscoped_empty_database_reports_an_explicit_empty_scope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    store = ResultStore(database)
    asyncio.run(store.initialize())
    asyncio.run(store.dispose())

    assert source_yields.main(['--database', str(database), '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 0,
        'source_yields': [],
        'targets': [],
    }

    assert source_yields.main(['--database', str(database)]) == 0
    assert capsys.readouterr().out.splitlines()[:3] == ['Targets: none', 'Kind: hostname', 'Run count: 0']

    assert source_yields.main(['--database', str(database), '--changes']) == 0
    assert capsys.readouterr().out.startswith('Targets: none\nComparison count: 0\n')


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

    assert capsys.readouterr().out.startswith('Target: example.test\nKind: hostname\nRun count: 2\n')


def test_default_table_ranks_by_unique_per_run_and_aligns_columns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert source_yields.main(['--database', str(database)]) == 0

    assert capsys.readouterr().out.splitlines() == [
        'Target: example.test',
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
    assert lines[:2] == ['Target: example.test', f'Kind: {kind}']
    assert ('RESOLVED' in lines[3]) is (kind == 'hostname')
    if kind == 'ip':
        assert [line.split() for line in lines[4:]] == [
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
    assert lines[:3] == ['Target: example.test', 'Kind: hostname', 'Run count: 1']
    assert [line.split() for line in lines[4:]] == [
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
    assert payload['target'] == 'example.test'
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
