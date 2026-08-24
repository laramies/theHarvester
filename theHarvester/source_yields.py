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

if TYPE_CHECKING:
    from collections.abc import Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Report per-source result yields from a theHarvester database.')
    parser.add_argument(
        '--database',
        type=Path,
        default=Path(ResultStore().database),
        help='Existing theHarvester SQLite database (default: %(default)s).',
    )
    parser.add_argument('--kind', choices=sorted(RESULT_KINDS), default='hostname', help='Result kind to compare.')
    parser.add_argument('--run-id', type=UUID, help='Report one completed run instead of aggregating every run.')
    parser.add_argument('--format', choices=('table', 'json'), default='table', help='Output format.')
    return parser


async def _collect(database: Path, kind: ResultKind, run_id: UUID | None) -> tuple[int, list[dict[str, str | int | float]]]:
    store = ResultStore(database)
    try:
        if run_id is not None:
            await store.load_run(run_id)
            run_ids = [run_id]
        else:
            run_ids = [UUID(str(run['run_id'])) for run in await store.list_runs(limit=None)]
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
        return len(run_ids), rows
    finally:
        await store.dispose()


def _table(kind: ResultKind, run_count: int, rows: list[dict[str, str | int | float]]) -> str:
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
    lines = [
        f'Kind: {kind}',
        f'Run count: {run_count}',
        '  '.join(label.ljust(widths[index]) for index, (_key, label) in enumerate(columns)).rstrip(),
    ]
    lines.extend(
        '  '.join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip() for values in formatted_rows
    )
    return '\n'.join(lines) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error(f'database does not exist: {args.database}')
    kind = cast('ResultKind', args.kind)
    try:
        run_count, rows = asyncio.run(_collect(args.database, kind, args.run_id))
    except LookupError as error:
        parser.error(str(error))
    if args.format == 'json':
        output = json.dumps({'kind': kind, 'run_count': run_count, 'source_yields': rows}, sort_keys=True) + '\n'
    else:
        output = _table(kind, run_count, rows)
    sys.stdout.write(output)
    return 0
