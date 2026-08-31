from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import UUID

from theHarvester.lib.database import ResultStore
from theHarvester.lib.evidence_types import RESULT_KINDS, ResultKind
from theHarvester.lib.hostname_comparison import canonical_target, hostname_comparison

if TYPE_CHECKING:
    from collections.abc import Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='harvest-report',
        description='Report source contributions and hostname changes from saved theHarvester runs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  harvest-report contributions --target example.test
  harvest-report hostname-changes --target example.test
  harvest-report hostname-changes --run-id RUN_ID
  harvest-report hostname-changes --target example.test --include-still-reported --format json

Hostname comparisons read finalized local evidence only and never run discovery or DNS.""",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        '--database',
        type=Path,
        default=Path(ResultStore().database),
        help='Existing theHarvester SQLite database (default: %(default)s).',
    )
    common.add_argument('--format', choices=('table', 'json'), default='table', help='Output format.')
    reports = parser.add_subparsers(dest='report', required=True)

    contributions = reports.add_parser(
        'contributions',
        parents=[common],
        help='Count what each source reported in saved runs.',
    )
    contributions.add_argument('--kind', choices=sorted(RESULT_KINDS), default='hostname', help='Result kind to compare.')
    scope = contributions.add_mutually_exclusive_group()
    scope.add_argument('--run-id', type=UUID, help='Report one completed run instead of aggregating every run.')
    scope.add_argument('--target', help='Report finalized runs for one exact canonical target.')
    scope.add_argument('--all-targets', action='store_true', help='Explicitly aggregate finalized runs across all targets.')

    changes = reports.add_parser(
        'hostname-changes',
        parents=[common],
        help='Compare hostname evidence in saved runs without discovery or DNS.',
        description='Compare hostname evidence in saved runs. This never runs discovery or DNS.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  harvest-report hostname-changes --target example.test
  harvest-report hostname-changes --run-id RUN_ID
  harvest-report hostname-changes --target example.test --include-still-reported --format json""",
    )
    change_scope = changes.add_mutually_exclusive_group()
    change_scope.add_argument('--run-id', type=UUID, help='Compare one completed run with its comparable previous run.')
    change_scope.add_argument('--target', help='Compare finalized runs for one exact canonical target.')
    changes.add_argument(
        '--include-still-reported',
        action='store_true',
        help='Include hostnames retained in both runs.',
    )

    reports.add_parser(
        'targets',
        parents=[common],
        help='List canonical targets and finalized-run counts.',
    )
    return parser


async def _list_targets(database: Path) -> list[dict[str, str | int]]:
    store = ResultStore(database)
    try:
        counts = Counter(canonical_target(run['target']) for run in await store.list_runs(limit=None))
        return [{'target': target, 'run_count': counts[target]} for target in sorted(counts)]
    finally:
        await store.dispose()


async def _compare_hostnames(
    database: Path,
    *,
    target: str | None = None,
    run_id: UUID | None = None,
    include_still_reported: bool = False,
) -> dict[str, object]:
    store = ResultStore(database)
    try:
        return await hostname_comparison(
            store,
            target=target,
            run_id=run_id,
            include_still_reported=include_still_reported,
        )
    finally:
        await store.dispose()


async def _collect(
    database: Path,
    kind: ResultKind,
    run_id: UUID | None,
    target: str | None = None,
    all_targets: bool = False,
) -> tuple[str | None, list[dict[str, str | int]], int, list[dict[str, str | int | float]]]:
    store = ResultStore(database)
    try:
        target_rows: list[dict[str, str | int]] = []
        if run_id is not None:
            selected_target = canonical_target((await store.load_run(run_id)).target)
            run_ids = [run_id]
        else:
            summaries = await store.list_runs(limit=None)
            selected_target = canonical_target(target) if target is not None else None
            if all_targets:
                counts = Counter(canonical_target(run['target']) for run in summaries)
                target_rows = [{'target': value, 'run_count': counts[value]} for value in sorted(counts)]
            elif selected_target is not None:
                summaries = [run for run in summaries if canonical_target(run['target']) == selected_target]
                if not summaries:
                    raise LookupError(f'target not found: {selected_target}; use harvest-report targets')
            else:
                targets = {canonical_target(run['target']) for run in summaries}
                if len(targets) > 1:
                    raise LookupError(f'database contains {len(targets)} canonical targets; use harvest-report targets')
                selected_target = next(iter(targets), None)
            run_ids = [UUID(str(run['run_id'])) for run in summaries]
        totals: defaultdict[str, Counter[str]] = defaultdict(Counter)
        for run_id in run_ids:
            for contribution in await store.source_contributions(run_id, kind=kind):
                totals[contribution.source].update(
                    runs=1,
                    reported=contribution.reported_count,
                    unique_to_source=contribution.unique_to_source_count,
                    shared_with_other_sources=contribution.shared_with_other_sources_count,
                    resolved=contribution.resolved_hostname_count,
                    unique_to_source_and_resolved=contribution.unique_to_source_and_resolved_count,
                )
        rows = []
        for source, counts in totals.items():
            row: dict[str, str | int | float] = {
                'source': source,
                'run_count': counts['runs'],
                'reported_count': counts['reported'],
                'unique_to_source_count': counts['unique_to_source'],
                'unique_to_source_count_per_run': counts['unique_to_source'] / counts['runs'],
                'shared_with_other_sources_count': counts['shared_with_other_sources'],
            }
            if kind == 'hostname':
                row['resolved_hostname_count'] = counts['resolved']
                row['unique_to_source_and_resolved_count'] = counts['unique_to_source_and_resolved']
                row['unique_to_source_and_resolved_count_per_run'] = counts['unique_to_source_and_resolved'] / counts['runs']
            rows.append(row)
        rows.sort(
            key=lambda row: (
                -float(row['unique_to_source_count_per_run']),
                -int(row['unique_to_source_count']),
                -int(row['reported_count']),
                str(row['source']),
            )
        )
        return selected_target, target_rows, len(run_ids), rows
    finally:
        await store.dispose()


def _table(
    kind: ResultKind,
    run_count: int,
    rows: list[dict[str, str | int | float]],
    target: str | None,
    targets: list[dict[str, str | int]],
) -> str:
    columns = [
        ('source', 'SOURCE'),
        ('run_count', 'RUNS'),
        ('reported_count', 'REPORTED'),
        ('unique_to_source_count', 'UNIQUE-TO-SOURCE'),
        ('unique_to_source_count_per_run', 'UNIQUE/RUN'),
        ('shared_with_other_sources_count', 'SHARED-WITH-OTHERS'),
    ]
    if kind == 'hostname':
        columns.extend(
            (
                ('resolved_hostname_count', 'RESOLVED'),
                ('unique_to_source_and_resolved_count', 'UNIQUE-AND-RESOLVED'),
                ('unique_to_source_and_resolved_count_per_run', 'UNIQUE-AND-RESOLVED/RUN'),
            )
        )
    formatted_rows = [
        [f'{row[key]:.2f}' if key.endswith('_per_run') else str(row[key]) for key, _label in columns] for row in rows
    ]
    widths = [
        max([len(label), *(len(values[index]) for values in formatted_rows)]) for index, (_key, label) in enumerate(columns)
    ]
    scope_lines = (
        [f'Target: {target}']
        if target is not None
        else ['Scope: all targets', _targets_table(targets).rstrip()]
        if targets
        else ['Targets: none']
    )
    lines = [
        *scope_lines,
        f'Kind: {kind}',
        f'Run count: {run_count}',
        '  '.join(label.ljust(widths[index]) for index, (_key, label) in enumerate(columns)).rstrip(),
    ]
    lines.extend(
        '  '.join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip() for values in formatted_rows
    )
    return '\n'.join(lines) + '\n'


def _targets_table(rows: list[dict[str, str | int]]) -> str:
    target_width = max([len('TARGET'), *(len(str(row['target'])) for row in rows)])
    lines = [f'{"TARGET".ljust(target_width)}  RUNS'.rstrip()]
    lines.extend(f'{str(row["target"]).ljust(target_width)}  {row["run_count"]}'.rstrip() for row in rows)
    return '\n'.join(lines) + '\n'


def _comparison_table(payload: dict[str, object]) -> str:
    comparisons = cast('list[dict[str, object]]', payload['comparisons'])
    differences = cast('list[dict[str, object]]', payload['hostname_differences'])
    scope = f'Target: {payload["target"]}' if payload['target'] is not None else 'Targets: none'
    lines = [scope, f'Comparison count: {payload["comparison_count"]}']
    summary_columns = (
        ('run_id', 'CURRENT RUN'),
        ('previous_comparable_run_id', 'PREVIOUS COMPARABLE RUN'),
        ('newly_reported', 'NEWLY REPORTED'),
        ('still_reported', 'STILL REPORTED'),
        ('no_longer_reported', 'NO LONGER REPORTED'),
        ('uncertain', 'UNCERTAIN'),
    )
    summary_rows = [
        {
            'run_id': comparison['run_id'],
            'previous_comparable_run_id': comparison['previous_comparable_run_id'] or '-',
            **cast('dict[str, int]', comparison['counts']),
        }
        for comparison in comparisons
    ]
    summary_widths = [max([len(label), *(len(str(row[key])) for row in summary_rows)]) for key, label in summary_columns]
    lines.append('  '.join(label.ljust(summary_widths[index]) for index, (_key, label) in enumerate(summary_columns)))
    lines.extend(
        '  '.join(str(row[key]).ljust(summary_widths[index]) for index, (key, _label) in enumerate(summary_columns))
        for row in summary_rows
    )
    lines.extend(f'{comparison["run_id"]}: {message}' for comparison in comparisons if (message := comparison.get('message')))
    change_columns = (
        ('difference', 'DIFFERENCE'),
        ('hostname', 'HOSTNAME'),
        ('sources', 'SOURCES'),
        ('one_source', 'ONE SOURCE'),
        ('resolution', 'RESOLUTION'),
        ('addressability', 'ADDRESSABILITY'),
        ('incomplete_sources', 'INCOMPLETE SOURCES'),
    )
    change_rows = []
    for row in differences:
        sources = row['sources_in_current_run'] or row['sources_in_previous_run']
        blockers = cast('list[dict[str, object]]', row['incomplete_comparison_sources'])
        change_rows.append(
            {
                'difference': str(row['change_type']).replace('_', ' ').upper(),
                'hostname': row['hostname'],
                'sources': ','.join(cast('list[str]', sources)) or '-',
                'one_source': 'yes' if row['reported_by_one_source'] else 'no',
                'resolution': f'{row["previous_resolution_evidence"]} -> {row["current_resolution_evidence"]}',
                'addressability': f'{row["previous_addressability"] or "-"} -> {row["current_addressability"] or "-"}',
                'incomplete_sources': ','.join(
                    ':'.join(
                        str(value or '-')
                        for value in (blocker['source'], blocker['status'], blocker['error_type'], blocker['stop_reason'])
                    )
                    for blocker in blockers
                )
                or '-',
            }
        )
    if not change_rows:
        lines.append('No hostname differences to display.')
        return '\n'.join(lines) + '\n'
    change_widths = [max(len(label), *(len(str(row[key])) for row in change_rows)) for key, label in change_columns]
    lines.append('  '.join(label.ljust(change_widths[index]) for index, (_key, label) in enumerate(change_columns)))
    lines.extend(
        '  '.join(str(row[key]).ljust(change_widths[index]) for index, (key, _label) in enumerate(change_columns)).rstrip()
        for row in change_rows
    )
    return '\n'.join(lines) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error(f'database does not exist: {args.database}')
    if args.report == 'targets':
        targets = asyncio.run(_list_targets(args.database))
        output = json.dumps({'targets': targets}, sort_keys=True) + '\n' if args.format == 'json' else _targets_table(targets)
        sys.stdout.write(output)
        return 0
    if args.report == 'hostname-changes':
        comparison: dict[str, object]
        try:
            if args.run_id is not None:
                comparison = asyncio.run(
                    _compare_hostnames(
                        args.database,
                        run_id=args.run_id,
                        include_still_reported=args.include_still_reported,
                    )
                )
            else:
                selected_target, _targets, _run_count, _rows = asyncio.run(_collect(args.database, 'hostname', None, args.target))
                if selected_target is None:
                    comparison = {
                        'target': None,
                        'comparison_count': 0,
                        'comparisons': [],
                        'hostname_differences': [],
                    }
                else:
                    comparison = asyncio.run(
                        _compare_hostnames(
                            args.database,
                            target=selected_target,
                            include_still_reported=args.include_still_reported,
                        )
                    )
        except LookupError as error:
            parser.error(str(error))
        output = json.dumps(comparison, sort_keys=True) + '\n' if args.format == 'json' else _comparison_table(comparison)
        sys.stdout.write(output)
        return 0
    kind = cast('ResultKind', args.kind)
    try:
        target, targets, run_count, rows = asyncio.run(_collect(args.database, kind, args.run_id, args.target, args.all_targets))
    except LookupError as error:
        parser.error(str(error))
    if args.format == 'json':
        payload = {'kind': kind, 'run_count': run_count, 'source_contributions': rows}
        if target is not None:
            payload['target'] = target
        else:
            payload['targets'] = targets
        output = json.dumps(payload, sort_keys=True) + '\n'
    else:
        output = _table(kind, run_count, rows, target, targets)
    sys.stdout.write(output)
    return 0
