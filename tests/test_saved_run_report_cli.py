import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from theHarvester import saved_run_report
from theHarvester.lib import database as database_module
from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution
from theHarvester.lib.database import ResultStore
from theHarvester.lib.evidence_types import RESULT_KINDS, ExecutionStatus

if TYPE_CHECKING:
    from pathlib import Path

RUN_ONE = UUID('11111111-1111-4111-8111-111111111111')
RUN_TIE_LATER = UUID('11111111-1111-4111-8111-111111111112')
RUN_TWO = UUID('22222222-2222-4222-8222-222222222222')


def test_help_exposes_plain_language_report_tasks(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['--help'])

    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert '{contributions,hostname-changes,targets}' in help_text
    assert '--changes' not in help_text


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


def test_jsonl_serialization_does_not_embed_saved_run_reports() -> None:
    completed = _completed_run(
        RUN_ONE,
        observations=(ResultObservation('alpha', 'hostname', 'alpha.example.test'),),
    )

    records = [json.loads(line) for line in completed.jsonl().splitlines()]

    assert all('source_contributions' not in record for record in records)
    assert all('hostname_comparison' not in record for record in records)


async def _create_comparison_database(database: Path) -> None:
    store = ResultStore(database)
    await store.initialize()
    await store.save_run(
        _completed_run(
            RUN_ONE,
            target='EXAMPLE.TEST.',
            observations=(
                ResultObservation('alpha', 'hostname', 'no-longer-reported.example.test'),
                ResultObservation('alpha', 'hostname', 'still-reported.example.test'),
                ResultObservation('beta', 'hostname', 'uncertain.example.test'),
            ),
            resolved_hostnames=('no-longer-reported.example.test',),
            source_statuses={'beta': ('partial', 'PreviousRunTimeout', 'previous-run-errors')},
            dns_status='completed',
        )
    )
    await store.save_run(
        _completed_run(
            RUN_TWO,
            observations=(
                ResultObservation('alpha', 'hostname', 'still-reported.example.test'),
                ResultObservation('alpha', 'hostname', 'newly-reported.example.test'),
                ResultObservation('beta', 'hostname', 'uncertain-newly-reported.example.test'),
            ),
            resolved_hostnames=('newly-reported.example.test', 'still-reported.example.test'),
            source_statuses={'beta': ('partial', 'TimeoutError', 'request-errors')},
            dns_status='completed',
            addressability={'newly-reported.example.test': 'currently-addressable'},
        )
    )
    await store.dispose()


async def _create_unreliable_dns_comparison_database(database: Path) -> None:
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

    assert saved_run_report.main(['targets', '--database', str(database)]) == 0

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

    assert saved_run_report.main(['targets', '--database', str(database), '--format', 'json']) == 0

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

    assert saved_run_report.main(['targets', '--database', str(database)]) == 0
    assert capsys.readouterr().out == 'TARGET  RUNS\n'
    assert saved_run_report.main(['targets', '--database', str(database), '--format', 'json']) == 0
    assert capsys.readouterr().out == '{"targets": []}\n'


def test_list_targets_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['targets', '--database', str(database), '--run-id', str(RUN_ONE)])

    assert error.value.code == 2
    assert 'unrecognized arguments: --run-id' in capsys.readouterr().err


def test_target_selects_only_matching_canonical_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    assert (
        saved_run_report.main(['contributions', '--database', str(database), '--target', 'example.test', '--format', 'json']) == 0
    )

    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 1,
        'source_contributions': [
            {
                'reported_count': 1,
                'resolved_hostname_count': 0,
                'run_count': 1,
                'shared_with_other_sources_count': 0,
                'source': 'alpha',
                'unique_to_source_and_resolved_count': 0,
                'unique_to_source_and_resolved_count_per_run': 0.0,
                'unique_to_source_count': 1,
                'unique_to_source_count_per_run': 1.0,
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

    assert saved_run_report.main(['contributions', '--database', str(database), '--target', requested, '--format', 'json']) == 0

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
        saved_run_report.main(['contributions', '--database', str(database), '--target', 'missing.example'])

    assert error.value.code == 2
    assert 'target not found: missing.example; use harvest-report targets' in capsys.readouterr().err


def test_target_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(
            ['contributions', '--database', str(database), '--target', 'example.test', '--run-id', str(RUN_ONE)]
        )

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_unscoped_report_refuses_to_mix_multiple_targets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['contributions', '--database', str(database)])

    assert error.value.code == 2
    message = capsys.readouterr().err
    assert '2 canonical targets' in message
    assert 'harvest-report targets' in message


def test_all_targets_explicitly_restores_mixed_target_json_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    assert saved_run_report.main(['contributions', '--database', str(database), '--all-targets', '--format', 'json']) == 0

    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 2,
        'source_contributions': [
            {
                'reported_count': 2,
                'resolved_hostname_count': 0,
                'run_count': 2,
                'shared_with_other_sources_count': 0,
                'source': 'alpha',
                'unique_to_source_and_resolved_count': 0,
                'unique_to_source_and_resolved_count_per_run': 0.0,
                'unique_to_source_count': 2,
                'unique_to_source_count_per_run': 1.0,
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

    assert saved_run_report.main(['contributions', '--database', str(database), '--all-targets']) == 0

    assert capsys.readouterr().out.splitlines()[:7] == [
        'Scope: all targets',
        'TARGET         RUNS',
        'example.test   1',
        'other.example  1',
        'Kind: hostname',
        'Run count: 2',
        'SOURCE  RUNS  REPORTED  UNIQUE-TO-SOURCE  UNIQUE/RUN  SHARED-WITH-OTHERS  RESOLVED  UNIQUE-AND-RESOLVED  UNIQUE-AND-RESOLVED/RUN',
    ]


@pytest.mark.parametrize('conflicting', ['--target'])
def test_all_targets_rejects_other_scope_selectors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    conflicting: str,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))
    args = ['contributions', '--database', str(database), '--all-targets', conflicting]
    if conflicting == '--target':
        args.append('example.test')

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(args)

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_all_targets_rejects_a_run_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_multi_target_database(database))

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['contributions', '--database', str(database), '--all-targets', '--run-id', str(RUN_ONE)])

    assert error.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err


def test_hostname_changes_distinguish_no_longer_reported_from_uncertain_using_persisted_source_outcomes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    assert (
        saved_run_report.main(['hostname-changes', '--database', str(database), '--run-id', str(RUN_TWO), '--format', 'json'])
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload['target'] == 'example.test'
    assert payload['comparison_count'] == 1
    assert payload['comparisons'][0] == {
        'previous_comparable_run_completed_at': '2026-08-23T12:01:01+00:00',
        'previous_comparable_run_id': str(RUN_ONE),
        'completed_at': '2026-08-23T12:02:01+00:00',
        'counts': {'newly_reported': 1, 'still_reported': 1, 'no_longer_reported': 1, 'uncertain': 2},
        'run_id': str(RUN_TWO),
        'compared_sources': ['alpha', 'beta'],
    }
    differences = {row['hostname']: row for row in payload['hostname_differences']}
    assert set(differences) == {
        'uncertain.example.test',
        'no-longer-reported.example.test',
        'newly-reported.example.test',
        'uncertain-newly-reported.example.test',
    }
    assert differences['newly-reported.example.test'] == {
        'previous_comparable_run_id': str(RUN_ONE),
        'incomplete_comparison_sources': [],
        'change_type': 'newly_reported',
        'current_addressability': 'currently-addressable',
        'current_dns_action_status': 'completed',
        'current_resolution_evidence': 'positive',
        'sources_in_current_run': ['alpha'],
        'hostname': 'newly-reported.example.test',
        'previous_addressability': None,
        'previous_dns_action_status': 'completed',
        'previous_resolution_evidence': 'not-checked',
        'sources_in_previous_run': [],
        'run_id': str(RUN_TWO),
        'reported_by_one_source': True,
    }
    assert differences['no-longer-reported.example.test']['change_type'] == 'no_longer_reported'
    assert differences['no-longer-reported.example.test']['incomplete_comparison_sources'] == []
    assert differences['no-longer-reported.example.test']['previous_resolution_evidence'] == 'positive'
    assert differences['uncertain.example.test']['change_type'] == 'uncertain'
    assert differences['uncertain.example.test']['incomplete_comparison_sources'] == [
        {
            'error_type': 'TimeoutError',
            'source': 'beta',
            'status': 'partial',
            'stop_reason': 'request-errors',
        }
    ]
    assert differences['uncertain-newly-reported.example.test']['change_type'] == 'uncertain'
    assert differences['uncertain-newly-reported.example.test']['sources_in_current_run'] == ['beta']
    assert differences['uncertain-newly-reported.example.test']['reported_by_one_source'] is True
    assert differences['uncertain-newly-reported.example.test']['incomplete_comparison_sources'] == [
        {
            'error_type': 'PreviousRunTimeout',
            'source': 'beta',
            'status': 'partial',
            'stop_reason': 'previous-run-errors',
        }
    ]


def test_target_hostname_changes_reports_every_run_pair_and_a_clear_null_previous_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    assert (
        saved_run_report.main(['hostname-changes', '--database', str(database), '--target', 'example.test', '--format', 'json'])
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload['comparison_count'] == 2
    assert payload['comparisons'][0] == {
        'previous_comparable_run_completed_at': None,
        'previous_comparable_run_id': None,
        'completed_at': '2026-08-23T12:01:01+00:00',
        'counts': {'newly_reported': 0, 'still_reported': 0, 'no_longer_reported': 0, 'uncertain': 0},
        'message': 'No earlier finalized run has the same target and source list.',
        'run_id': str(RUN_ONE),
        'compared_sources': ['alpha', 'beta'],
    }
    assert payload['comparisons'][1]['previous_comparable_run_id'] == str(RUN_ONE)
    assert {row['run_id'] for row in payload['hostname_differences']} == {str(RUN_TWO)}


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
        saved_run_report.main(
            ['hostname-changes', '--database', str(database), '--run-id', str(RUN_TIE_LATER), '--format', 'json']
        )
        == 0
    )

    comparison = json.loads(capsys.readouterr().out)['comparisons'][0]
    assert comparison['previous_comparable_run_id'] == str(RUN_ONE)


def test_include_still_reported_adds_unchanged_hostname_rows_without_changing_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    assert (
        saved_run_report.main(
            [
                'hostname-changes',
                '--database',
                str(database),
                '--run-id',
                str(RUN_TWO),
                '--include-still-reported',
                '--format',
                'json',
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    still_reported = [row for row in payload['hostname_differences'] if row['change_type'] == 'still_reported']
    assert [(row['hostname'], row['reported_by_one_source']) for row in still_reported] == [('still-reported.example.test', True)]
    assert payload['comparisons'][0]['counts']['still_reported'] == 1


def test_failed_dns_action_does_not_claim_a_sourced_hostname_was_checked(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_unreliable_dns_comparison_database(database))

    assert (
        saved_run_report.main(
            [
                'hostname-changes',
                '--database',
                str(database),
                '--run-id',
                str(RUN_TWO),
                '--include-still-reported',
                '--format',
                'json',
            ]
        )
        == 0
    )

    row = json.loads(capsys.readouterr().out)['hostname_differences'][0]
    assert row['current_dns_action_status'] == 'failed'
    assert row['current_resolution_evidence'] == 'not-checked'


def test_hostname_changes_table_is_human_readable_and_explains_uncertain_rows(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    assert saved_run_report.main(['hostname-changes', '--database', str(database), '--run-id', str(RUN_TWO)]) == 0

    output = capsys.readouterr().out
    assert output.startswith('Target: example.test\nComparison count: 1\n')
    assert 'NEWLY REPORTED  STILL REPORTED  NO LONGER REPORTED  UNCERTAIN' in output
    lines = output.splitlines()
    assert lines[4].split() == [
        'DIFFERENCE',
        'HOSTNAME',
        'SOURCES',
        'ONE',
        'SOURCE',
        'RESOLUTION',
        'ADDRESSABILITY',
        'INCOMPLETE',
        'SOURCES',
    ]
    assert lines[5].split()[:3] == ['NEWLY', 'REPORTED', 'newly-reported.example.test']
    assert lines[6].split()[:4] == ['NO', 'LONGER', 'REPORTED', 'no-longer-reported.example.test']
    assert lines[7].split()[:2] == ['UNCERTAIN', 'uncertain-newly-reported.example.test']
    assert lines[8].split()[:2] == ['UNCERTAIN', 'uncertain.example.test']
    assert 'beta:partial:TimeoutError:request-errors' in output
    assert 'beta:partial:PreviousRunTimeout:previous-run-errors' in output


def test_hostname_changes_table_explains_when_a_run_has_no_comparable_previous_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    assert saved_run_report.main(['hostname-changes', '--database', str(database), '--run-id', str(RUN_ONE)]) == 0

    output = capsys.readouterr().out
    assert f'{RUN_ONE}: No earlier finalized run has the same target and source list.' in output


@pytest.mark.parametrize(
    'args',
    [
        ['contributions', '--include-still-reported'],
        ['hostname-changes', '--kind', 'ip'],
        ['hostname-changes', '--all-targets'],
        ['hostname-changes', 'targets'],
    ],
)
def test_hostname_changes_rejects_ambiguous_or_non_hostname_arguments(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_comparison_database(database))

    with pytest.raises(SystemExit) as error:
        saved_run_report.main([*args, '--database', str(database)])

    assert error.value.code == 2
    assert capsys.readouterr().err


def test_help_makes_persisted_read_only_hostname_changes_obvious(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['hostname-changes', '--help'])

    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert 'never runs discovery or DNS' in help_text
    assert 'usage: harvest-report hostname-changes' in help_text
    assert '[--run-id RUN_ID | --target TARGET]' in help_text
    assert '--include-still-reported' in help_text


def test_unscoped_empty_database_reports_an_explicit_empty_scope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    store = ResultStore(database)
    asyncio.run(store.initialize())
    asyncio.run(store.dispose())

    assert saved_run_report.main(['contributions', '--database', str(database), '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out) == {
        'kind': 'hostname',
        'run_count': 0,
        'source_contributions': [],
        'targets': [],
    }

    assert saved_run_report.main(['contributions', '--database', str(database)]) == 0
    assert capsys.readouterr().out.splitlines()[:3] == ['Targets: none', 'Kind: hostname', 'Run count: 0']

    assert saved_run_report.main(['hostname-changes', '--database', str(database)]) == 0
    assert capsys.readouterr().out.startswith('Targets: none\nComparison count: 0\n')


def test_missing_database_fails_without_creating_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'missing.sqlite'

    with pytest.raises(SystemExit) as error:
        saved_run_report.main(['contributions', '--database', str(database)])

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

    assert saved_run_report.main(['contributions']) == 0

    assert capsys.readouterr().out.startswith('Target: example.test\nKind: hostname\nRun count: 2\n')


def test_default_table_ranks_by_unique_per_run_and_aligns_columns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert saved_run_report.main(['contributions', '--database', str(database)]) == 0

    assert capsys.readouterr().out.splitlines() == [
        'Target: example.test',
        'Kind: hostname',
        'Run count: 2',
        'SOURCE  RUNS  REPORTED  UNIQUE-TO-SOURCE  UNIQUE/RUN  SHARED-WITH-OTHERS  RESOLVED  UNIQUE-AND-RESOLVED  UNIQUE-AND-RESOLVED/RUN',
        'gamma   1     1         1                 1.00        0                   0         0                    0.00',
        'alpha   2     3         1                 0.50        2                   3         1                    0.50',
        'beta    2     3         1                 0.50        2                   2         0                    0.00',
    ]


@pytest.mark.parametrize('kind', sorted(RESULT_KINDS))
def test_kind_accepts_every_result_kind_and_only_hostname_shows_resolution_columns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    database = tmp_path / 'runs.sqlite'
    asyncio.run(_create_database(database))

    assert saved_run_report.main(['contributions', '--database', str(database), '--kind', kind]) == 0

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

    assert saved_run_report.main(['contributions', '--database', str(database), '--run-id', str(RUN_ONE)]) == 0

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
        saved_run_report.main(['contributions', '--database', str(database), '--run-id', str(missing_run)])

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

    assert saved_run_report.main(['contributions', '--database', str(database), '--kind', kind, '--format', 'json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['target'] == 'example.test'
    assert payload['kind'] == kind
    assert payload['run_count'] == 2
    assert [row['source'] for row in payload['source_contributions']] == ['gamma', 'alpha', 'beta']
    resolution_fields = {
        'resolved_hostname_count',
        'unique_to_source_and_resolved_count',
        'unique_to_source_and_resolved_count_per_run',
    }
    assert all(resolution_fields <= row.keys() for row in payload['source_contributions']) is (kind == 'hostname')
    assert {row['source']: row['run_count'] for row in payload['source_contributions']} == {'alpha': 2, 'beta': 2, 'gamma': 1}
    assert {row['source']: row['unique_to_source_count_per_run'] for row in payload['source_contributions']} == (
        {'alpha': 0.5, 'beta': 0.5, 'gamma': 1.0} if kind == 'hostname' else {'alpha': 0.0, 'beta': 0.0, 'gamma': 1.0}
    )
