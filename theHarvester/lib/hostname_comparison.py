from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from theHarvester.lib.target_identity import normalize_saved_target

if TYPE_CHECKING:
    from datetime import datetime

    from theHarvester.lib.database import ResultStore
    from theHarvester.lib.evidence_types import ExecutionStatus


HostnameDifferenceType = Literal['newly_reported', 'still_reported', 'no_longer_reported', 'uncertain']
ResolutionEvidence = Literal['positive', 'not-retained', 'not-checked']


@dataclass(frozen=True, slots=True)
class ComparisonSourceOutcome:
    source: str
    status: ExecutionStatus
    error_type: str | None
    stop_reason: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            'source': self.source,
            'status': self.status,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, slots=True)
class ComparableRunEvidence:
    run_id: UUID
    target: str
    completed_at: datetime
    source_outcomes: tuple[ComparisonSourceOutcome, ...]
    hostname_sources: tuple[tuple[str, tuple[str, ...]], ...]
    resolved_hostnames: frozenset[str]
    dns_action_status: ExecutionStatus | None
    addressability: tuple[tuple[str, str], ...]

    @property
    def compared_sources(self) -> tuple[str, ...]:
        return tuple(outcome.source for outcome in self.source_outcomes)


def _resolution(run: ComparableRunEvidence, hostname: str) -> ResolutionEvidence:
    if hostname in run.resolved_hostnames:
        return 'positive'
    if hostname not in dict(run.hostname_sources) or run.dns_action_status != 'completed':
        return 'not-checked'
    return 'not-retained'


def _incomplete_outcomes(
    run: ComparableRunEvidence,
    sources: tuple[str, ...],
) -> list[ComparisonSourceOutcome]:
    outcomes = {outcome.source: outcome for outcome in run.source_outcomes}
    return [outcomes[source] for source in sources if outcomes[source].status != 'completed']


def _difference_row(
    current: ComparableRunEvidence,
    previous: ComparableRunEvidence,
    hostname: str,
) -> tuple[HostnameDifferenceType, dict[str, object]]:
    previous_sources = dict(previous.hostname_sources).get(hostname, ())
    current_sources = dict(current.hostname_sources).get(hostname, ())
    incomplete_sources: list[ComparisonSourceOutcome] = []
    if not previous_sources:
        incomplete_sources = _incomplete_outcomes(previous, current_sources)
        difference: HostnameDifferenceType = 'uncertain' if incomplete_sources else 'newly_reported'
    elif current_sources:
        difference = 'still_reported'
    else:
        incomplete_sources = _incomplete_outcomes(current, previous_sources)
        difference = 'uncertain' if incomplete_sources else 'no_longer_reported'
    reported_sources = current_sources or previous_sources
    return difference, {
        'run_id': str(current.run_id),
        'previous_comparable_run_id': str(previous.run_id),
        'change_type': difference,
        'hostname': hostname,
        'sources_in_previous_run': list(previous_sources),
        'sources_in_current_run': list(current_sources),
        'reported_by_one_source': len(reported_sources) == 1,
        'incomplete_source_outcomes': [outcome.to_dict() for outcome in incomplete_sources],
        'previous_resolution_evidence': _resolution(previous, hostname),
        'current_resolution_evidence': _resolution(current, hostname),
        'previous_dns_action_status': previous.dns_action_status,
        'current_dns_action_status': current.dns_action_status,
        'previous_addressability': dict(previous.addressability).get(hostname),
        'current_addressability': dict(current.addressability).get(hostname),
    }


async def hostname_comparison(
    store: ResultStore,
    *,
    target: str | None = None,
    run_id: UUID | None = None,
    include_still_reported: bool = False,
) -> dict[str, object]:
    summaries = await store.list_runs(limit=None)
    if run_id is not None:
        current = await store.load_hostname_comparison_run(run_id)
        selected_target = normalize_saved_target(current.target)
        selected_ids = {run_id}
    elif target is not None:
        selected_target = normalize_saved_target(target)
        selected_ids = {
            UUID(str(summary['run_id'])) for summary in summaries if normalize_saved_target(summary['target']) == selected_target
        }
    else:
        raise ValueError('target or run_id is required')
    target_runs = [
        await store.load_hostname_comparison_run(UUID(str(summary['run_id'])))
        for summary in summaries
        if normalize_saved_target(summary['target']) == selected_target
    ]
    target_runs.sort(key=lambda run: (run.completed_at, str(run.run_id)))
    previous_by_sources: dict[tuple[str, ...], ComparableRunEvidence] = {}
    comparisons: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    difference_order = {'newly_reported': 0, 'no_longer_reported': 1, 'uncertain': 2, 'still_reported': 3}
    for current in target_runs:
        previous = previous_by_sources.get(current.compared_sources)
        previous_by_sources[current.compared_sources] = current
        if current.run_id not in selected_ids:
            continue
        counts = {'newly_reported': 0, 'still_reported': 0, 'no_longer_reported': 0, 'uncertain': 0}
        comparison: dict[str, object] = {
            'run_id': str(current.run_id),
            'completed_at': current.completed_at.isoformat(),
            'previous_comparable_run_id': str(previous.run_id) if previous else None,
            'previous_comparable_run_completed_at': previous.completed_at.isoformat() if previous else None,
            'compared_sources': list(current.compared_sources),
            'counts': counts,
        }
        if previous is None:
            comparison['message'] = 'No earlier finalized run has the same target and source list.'
        else:
            hostnames = sorted(set(dict(previous.hostname_sources)) | set(dict(current.hostname_sources)))
            comparison_rows = []
            for hostname in hostnames:
                difference, row = _difference_row(current, previous, hostname)
                counts[difference] += 1
                if difference != 'still_reported' or include_still_reported:
                    comparison_rows.append(row)
            rows.extend(
                sorted(
                    comparison_rows,
                    key=lambda row: (difference_order[str(row['change_type'])], str(row['hostname'])),
                )
            )
        comparisons.append(comparison)
    return {
        'target': selected_target,
        'comparison_count': len(comparisons),
        'comparisons': comparisons,
        'hostname_differences': rows,
    }
