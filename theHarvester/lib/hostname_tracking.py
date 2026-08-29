from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.result_values import normalize_asn, normalize_ip, normalize_prefix

if TYPE_CHECKING:
    from datetime import datetime

    from theHarvester.lib.database import ResultStore
    from theHarvester.lib.evidence_types import ExecutionStatus


ChangeStatus = Literal['new', 'persisting', 'missing', 'inconclusive']
ResolutionEvidence = Literal['positive', 'not-retained', 'not-checked']


def canonical_target(value: object) -> str:
    target = str(value).strip()
    if target[:2].casefold() == 'as' and target[2:].isascii() and target[2:].isdecimal():
        return normalize_asn(target)
    if '/' in target:
        try:
            return normalize_prefix(target)
        except ValueError:
            pass
    try:
        return normalize_ip(target, label='target')
    except ValueError:
        pass
    try:
        hostname = normalize_hostname(target)
    except ValueError:
        return target
    return hostname if '.' in hostname else target


@dataclass(frozen=True, slots=True)
class TrackingSourceOutcome:
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
class TrackingRunEvidence:
    run_id: UUID
    target: str
    completed_at: datetime
    source_outcomes: tuple[TrackingSourceOutcome, ...]
    hostname_sources: tuple[tuple[str, tuple[str, ...]], ...]
    resolved_hostnames: frozenset[str]
    dns_action_status: ExecutionStatus | None
    addressability: tuple[tuple[str, str], ...]

    @property
    def source_cohort(self) -> tuple[str, ...]:
        return tuple(outcome.source for outcome in self.source_outcomes)


def _resolution(run: TrackingRunEvidence, hostname: str) -> ResolutionEvidence:
    if hostname in run.resolved_hostnames:
        return 'positive'
    if hostname not in dict(run.hostname_sources) or run.dns_action_status != 'completed':
        return 'not-checked'
    return 'not-retained'


def _blocking_outcomes(run: TrackingRunEvidence, sources: tuple[str, ...]) -> list[TrackingSourceOutcome]:
    outcomes = {outcome.source: outcome for outcome in run.source_outcomes}
    return [outcomes[source] for source in sources if outcomes[source].status != 'completed']


def _change_row(
    current: TrackingRunEvidence,
    baseline: TrackingRunEvidence,
    hostname: str,
) -> tuple[ChangeStatus, dict[str, object]]:
    previous_sources = dict(baseline.hostname_sources).get(hostname, ())
    current_sources = dict(current.hostname_sources).get(hostname, ())
    blocking_sources: list[TrackingSourceOutcome] = []
    if not previous_sources:
        blocking_sources = _blocking_outcomes(baseline, current_sources)
        change: ChangeStatus = 'inconclusive' if blocking_sources else 'new'
    elif current_sources:
        change = 'persisting'
    else:
        blocking_sources = _blocking_outcomes(current, previous_sources)
        change = 'inconclusive' if blocking_sources else 'missing'
    exclusive_sources = current_sources or previous_sources
    return change, {
        'run_id': str(current.run_id),
        'baseline_run_id': str(baseline.run_id),
        'change': change,
        'hostname': hostname,
        'previous_sources': list(previous_sources),
        'current_sources': list(current_sources),
        'source_exclusive': len(exclusive_sources) == 1,
        'blocking_sources': [outcome.to_dict() for outcome in blocking_sources],
        'previous_resolution_evidence': _resolution(baseline, hostname),
        'current_resolution_evidence': _resolution(current, hostname),
        'previous_dns_action_status': baseline.dns_action_status,
        'current_dns_action_status': current.dns_action_status,
        'previous_addressability': dict(baseline.addressability).get(hostname),
        'current_addressability': dict(current.addressability).get(hostname),
    }


async def hostname_tracking_projection(
    store: ResultStore,
    *,
    target: str | None = None,
    run_id: UUID | None = None,
    include_persisting: bool = False,
) -> dict[str, object]:
    summaries = await store.list_runs(limit=None)
    if run_id is not None:
        current = await store.load_hostname_tracking_run(run_id)
        selected_target = canonical_target(current.target)
        selected_ids = {run_id}
    elif target is not None:
        selected_target = canonical_target(target)
        selected_ids = {
            UUID(str(summary['run_id'])) for summary in summaries if canonical_target(summary['target']) == selected_target
        }
    else:
        raise ValueError('target or run_id is required')
    target_runs = [
        await store.load_hostname_tracking_run(UUID(str(summary['run_id'])))
        for summary in summaries
        if canonical_target(summary['target']) == selected_target
    ]
    target_runs.sort(key=lambda run: (run.completed_at, str(run.run_id)))
    previous_by_cohort: dict[tuple[str, ...], TrackingRunEvidence] = {}
    comparisons: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    change_order = {'new': 0, 'missing': 1, 'inconclusive': 2, 'persisting': 3}
    for current in target_runs:
        baseline = previous_by_cohort.get(current.source_cohort)
        previous_by_cohort[current.source_cohort] = current
        if current.run_id not in selected_ids:
            continue
        counts = {'new': 0, 'persisting': 0, 'missing': 0, 'inconclusive': 0}
        comparison: dict[str, object] = {
            'run_id': str(current.run_id),
            'completed_at': current.completed_at.isoformat(),
            'baseline_run_id': str(baseline.run_id) if baseline else None,
            'baseline_completed_at': baseline.completed_at.isoformat() if baseline else None,
            'source_cohort': list(current.source_cohort),
            'counts': counts,
        }
        if baseline is None:
            comparison['message'] = 'No previous finalized run has the same source cohort.'
        else:
            hostnames = sorted(set(dict(baseline.hostname_sources)) | set(dict(current.hostname_sources)))
            comparison_rows = []
            for hostname in hostnames:
                change, row = _change_row(current, baseline, hostname)
                counts[change] += 1
                if change != 'persisting' or include_persisting:
                    comparison_rows.append(row)
            rows.extend(sorted(comparison_rows, key=lambda row: (change_order[str(row['change'])], str(row['hostname']))))
        comparisons.append(comparison)
    return {
        'target': selected_target,
        'comparison_count': len(comparisons),
        'comparisons': comparisons,
        'hostname_changes': rows,
    }
