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
from theHarvester.lib.hostname_tracking import canonical_target, hostname_tracking_projection

if TYPE_CHECKING:
    from collections.abc import Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='harvest-yields',
        description='Report per-source result yields from a theHarvester database.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  harvest-yields --target example.test
  harvest-yields --target example.test --changes
  harvest-yields --run-id RUN_ID --changes
  harvest-yields --target example.test --changes --include-persisting --format json

Change reports read finalized local evidence only and never run discovery or DNS.""",
    )
    parser.add_argument(
        '--database',
        type=Path,
        default=Path(ResultStore().database),
        help='Existing theHarvester SQLite database (default: %(default)s).',
    )
    parser.add_argument('--kind', choices=sorted(RESULT_KINDS), default='hostname', help='Result kind to compare.')
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--run-id', type=UUID, help='Report one completed run instead of aggregating every run.')
    scope.add_argument('--list-targets', action='store_true', help='List canonical targets and finalized-run counts.')
    scope.add_argument('--target', help='Report finalized runs for one exact canonical target.')
    scope.add_argument('--all-targets', action='store_true', help='Explicitly aggregate finalized runs across all targets.')
    parser.add_argument(
        '--changes',
        action='store_true',
        help='Compare persisted hostname evidence between comparable finalized runs; never runs discovery or DNS.',
    )
    parser.add_argument(
        '--include-persisting',
        action='store_true',
        help='Include persisting hostname rows in a --changes report.',
    )
    parser.add_argument('--format', choices=('table', 'json'), default='table', help='Output format.')
    return parser


async def _list_targets(database: Path) -> list[dict[str, str | int]]:
    store = ResultStore(database)
    try:
        counts = Counter(canonical_target(run['target']) for run in await store.list_runs(limit=None))
        return [{'target': target, 'run_count': counts[target]} for target in sorted(counts)]
    finally:
        await store.dispose()


async def _changes(
    database: Path,
    *,
    target: str | None = None,
    run_id: UUID | None = None,
    include_persisting: bool = False,
) -> dict[str, object]:
    store = ResultStore(database)
    try:
        return await hostname_tracking_projection(
            store,
            target=target,
            run_id=run_id,
            include_persisting=include_persisting,
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
                    raise LookupError(f'target not found: {selected_target}; use --list-targets')
            else:
                targets = {canonical_target(run['target']) for run in summaries}
                if len(targets) > 1:
                    raise LookupError(f'database contains {len(targets)} canonical targets; use --list-targets')
                selected_target = next(iter(targets), None)
            run_ids = [UUID(str(run['run_id'])) for run in summaries]
        totals: defaultdict[str, Counter[str]] = defaultdict(Counter)
        for run_id in run_ids:
            for source_yield in await store.source_yields(run_id, kind=kind):
                totals[source_yield.source].update(
                    runs=1,
                    observed=source_yield.observed_result_count,
                    unique=source_yield.unique_result_count,
                    shared=source_yield.shared_result_count,
                    resolved=source_yield.resolved_hostname_count,
                    unique_resolved=source_yield.unique_resolved_hostname_count,
                )
        rows = []
        for source, counts in totals.items():
            row: dict[str, str | int | float] = {
                'source': source,
                'run_count': counts['runs'],
                'observed_result_count': counts['observed'],
                'unique_result_count': counts['unique'],
                'unique_result_count_per_run': counts['unique'] / counts['runs'],
                'shared_result_count': counts['shared'],
            }
            if kind == 'hostname':
                row['resolved_hostname_count'] = counts['resolved']
                row['unique_resolved_hostname_count'] = counts['unique_resolved']
                row['unique_resolved_hostname_count_per_run'] = counts['unique_resolved'] / counts['runs']
            rows.append(row)
        rows.sort(
            key=lambda row: (
                -float(row['unique_result_count_per_run']),
                -int(row['unique_result_count']),
                -int(row['observed_result_count']),
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
        ('observed_result_count', 'OBSERVED'),
        ('unique_result_count', 'UNIQUE'),
        ('unique_result_count_per_run', 'UNIQUE/RUN'),
        ('shared_result_count', 'SHARED'),
    ]
    if kind == 'hostname':
        columns.extend(
            (
                ('resolved_hostname_count', 'RESOLVED'),
                ('unique_resolved_hostname_count', 'UNIQUE-RESOLVED'),
                ('unique_resolved_hostname_count_per_run', 'UNIQUE-RESOLVED/RUN'),
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


def _tracking_table(payload: dict[str, object]) -> str:
    comparisons = cast('list[dict[str, object]]', payload['comparisons'])
    changes = cast('list[dict[str, object]]', payload['hostname_changes'])
    scope = f'Target: {payload["target"]}' if payload['target'] is not None else 'Targets: none'
    lines = [scope, f'Comparison count: {payload["comparison_count"]}']
    summary_columns = (
        ('run_id', 'CURRENT RUN'),
        ('baseline_run_id', 'BASELINE RUN'),
        ('new', 'NEW'),
        ('persisting', 'PERSISTING'),
        ('missing', 'MISSING'),
        ('inconclusive', 'INCONCLUSIVE'),
    )
    summary_rows = [
        {
            'run_id': comparison['run_id'],
            'baseline_run_id': comparison['baseline_run_id'] or '-',
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
        ('change', 'CHANGE'),
        ('hostname', 'HOSTNAME'),
        ('sources', 'SOURCES'),
        ('exclusive', 'EXCLUSIVE'),
        ('resolution', 'RESOLUTION'),
        ('addressability', 'ADDRESSABILITY'),
        ('blocking', 'BLOCKING SOURCES'),
    )
    change_rows = []
    for row in changes:
        sources = row['current_sources'] or row['previous_sources']
        blockers = cast('list[dict[str, object]]', row['blocking_sources'])
        change_rows.append(
            {
                'change': str(row['change']).upper(),
                'hostname': row['hostname'],
                'sources': ','.join(cast('list[str]', sources)) or '-',
                'exclusive': 'yes' if row['source_exclusive'] else 'no',
                'resolution': f'{row["previous_resolution_evidence"]} -> {row["current_resolution_evidence"]}',
                'addressability': f'{row["previous_addressability"] or "-"} -> {row["current_addressability"] or "-"}',
                'blocking': ','.join(
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
        lines.append('No hostname changes to display.')
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
    if args.include_persisting and not args.changes:
        parser.error('--include-persisting requires --changes')
    if args.changes and args.kind != 'hostname':
        parser.error('--changes supports hostname evidence only; omit --kind or use --kind hostname')
    if args.changes and args.list_targets:
        parser.error('--changes cannot be combined with --list-targets')
    if args.changes and args.all_targets:
        parser.error('--changes requires one target and cannot be combined with --all-targets')
    if args.list_targets:
        targets = asyncio.run(_list_targets(args.database))
        output = json.dumps({'targets': targets}, sort_keys=True) + '\n' if args.format == 'json' else _targets_table(targets)
        sys.stdout.write(output)
        return 0
    kind = cast('ResultKind', args.kind)
    if args.changes:
        changes: dict[str, object]
        try:
            if args.run_id is not None:
                changes = asyncio.run(_changes(args.database, run_id=args.run_id, include_persisting=args.include_persisting))
            else:
                selected_target, _targets, _run_count, _rows = asyncio.run(_collect(args.database, kind, None, args.target))
                if selected_target is None:
                    changes = {
                        'target': None,
                        'comparison_count': 0,
                        'comparisons': [],
                        'hostname_changes': [],
                    }
                else:
                    changes = asyncio.run(
                        _changes(
                            args.database,
                            target=selected_target,
                            include_persisting=args.include_persisting,
                        )
                    )
        except LookupError as error:
            parser.error(str(error))
        output = json.dumps(changes, sort_keys=True) + '\n' if args.format == 'json' else _tracking_table(changes)
        sys.stdout.write(output)
        return 0
    try:
        target, targets, run_count, rows = asyncio.run(_collect(args.database, kind, args.run_id, args.target, args.all_targets))
    except LookupError as error:
        parser.error(str(error))
    if args.format == 'json':
        payload = {'kind': kind, 'run_count': run_count, 'source_yields': rows}
        if target is not None:
            payload['target'] = target
        else:
            payload['targets'] = targets
        output = json.dumps(payload, sort_keys=True) + '\n'
    else:
        output = _table(kind, run_count, rows, target, targets)
    sys.stdout.write(output)
    return 0
