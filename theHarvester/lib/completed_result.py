import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Self, get_args
from uuid import UUID, uuid4

ResultKind = Literal[
    'analytics',
    'api-endpoint',
    'asn',
    'breach',
    'cms',
    'dns-recursive-classification',
    'dns-recursive-finding',
    'dns-recursive-summary',
    'email',
    'framework',
    'hostname',
    'infostealer',
    'interesting-url',
    'ip-address',
    'language',
    'linkedin-link',
    'linkedin-person',
    'person',
    'server',
    'screenshot',
    'shodan',
    'takeover',
    'twitter-person',
    'url',
    'vhost',
]
ExecutionStatus = Literal['completed', 'partial', 'failed', 'rate-limited', 'skipped']

SCHEMA_VERSION = 'theharvester-results-v1'
RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))
EXECUTION_STATUSES: frozenset[str] = frozenset(get_args(ExecutionStatus))


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


@dataclass(frozen=True, order=True, slots=True)
class ResultObservation:
    source: str
    kind: ResultKind
    value: str

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError('observation source must not be empty')
        if self.kind not in RESULT_KINDS:
            raise ValueError(f'unknown observation kind: {self.kind}')
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError('observation value must be a non-empty string')


@dataclass(frozen=True, slots=True)
class SourceExecution:
    """Record one source invocation without overstating the provider outcome.

    ``completed`` means the adapter returned normally. More precise statuses are
    used only when the adapter reports them or raises an exception. ``result_count``
    is the number of normalized, deduplicated observations attributed to the source.
    """

    source: str
    status: ExecutionStatus
    duration_ms: float
    result_count: int
    error_type: str | None = None
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError('source must not be empty')
        if self.status not in EXECUTION_STATUSES:
            raise ValueError(f'unknown execution status: {self.status}')
        if self.duration_ms < 0 or self.result_count < 0:
            raise ValueError('execution duration and result count must not be negative')

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'source': self.source,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, slots=True)
class SourceYield:
    source: str
    observed_result_count: int
    unique_result_count: int
    shared_result_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            'source': self.source,
            'observed_result_count': self.observed_result_count,
            'unique_result_count': self.unique_result_count,
            'shared_result_count': self.shared_result_count,
        }


@dataclass(frozen=True, slots=True)
class CompletedResult:
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    results: tuple[tuple[ResultKind, str], ...]
    source_executions: tuple[SourceExecution, ...] = ()
    observations: tuple[ResultObservation, ...] = ()

    def __post_init__(self) -> None:
        if not self.target.strip():
            raise ValueError('target must not be empty')
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError('started_at must be timezone-aware')
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError('completed_at must be timezone-aware')
        if self.completed_at < self.started_at:
            raise ValueError('completed_at must not be earlier than started_at')
        if not isinstance(self.run_id, UUID):
            raise ValueError('run_id must be a UUID')
        if any(kind not in RESULT_KINDS or not isinstance(value, str) or not value.strip() for kind, value in self.results):
            raise ValueError('results must contain known kinds and non-empty string values')
        if self.results != tuple(sorted(set(self.results))):
            raise ValueError('results must be deduplicated and sorted')
        if self.observations != tuple(sorted(set(self.observations))):
            raise ValueError('observations must be deduplicated and sorted')
        result_set = set(self.results)
        if any((observation.kind, observation.value) not in result_set for observation in self.observations):
            raise ValueError('every observation must reference a completed result')
        execution_sources = [execution.source for execution in self.source_executions]
        execution_source_set = set(execution_sources)
        if len(execution_sources) != len(execution_source_set):
            raise ValueError('source executions must be unique')
        if any(observation.source not in execution_source_set for observation in self.observations):
            raise ValueError('every observation must reference a matching source execution')
        observation_counts = Counter(observation.source for observation in self.observations)
        if any(execution.result_count != observation_counts[execution.source] for execution in self.source_executions):
            raise ValueError('source execution result count must match its attributed observations')

    @classmethod
    def finish(
        cls,
        *,
        run_id: UUID | None = None,
        target: str,
        started_at: datetime,
        completed_at: datetime,
        groups: Mapping[ResultKind, Iterable[str]],
        source_executions: Iterable[SourceExecution] = (),
        observations: Iterable[ResultObservation] = (),
    ) -> Self:
        results: set[tuple[ResultKind, str]] = set()
        for kind, values in groups.items():
            if kind not in RESULT_KINDS:
                raise ValueError(f'unknown result kind: {kind}')
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError('results must contain non-empty string values')
                results.add((kind, value.strip()))
        return cls(
            run_id=run_id or uuid4(),
            target=target.strip(),
            started_at=started_at,
            completed_at=completed_at,
            results=tuple(sorted(results)),
            source_executions=tuple(source_executions),
            observations=tuple(sorted(set(observations))),
        )

    def evidence_dict(self) -> dict[str, object]:
        incomplete = {'partial', 'failed', 'rate-limited', 'skipped'}
        status = 'complete'
        if self.source_executions and all(execution.status == 'failed' for execution in self.source_executions):
            status = 'failed'
        elif any(execution.status in incomplete for execution in self.source_executions):
            status = 'partial'
        return {
            'run_id': str(self.run_id),
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'status': status,
            'results': self._result_records(),
            'source_executions': [execution.to_dict() for execution in self.source_executions],
        }

    def jsonl(self) -> str:
        counts = Counter(kind for kind, _value in self.results)
        records = [
            {
                'completed_at': _isoformat_utc(self.completed_at),
                'counts': dict(sorted(counts.items())),
                'result_count': len(self.results),
                'run_id': str(self.run_id),
                'schema_version': SCHEMA_VERSION,
                'started_at': _isoformat_utc(self.started_at),
                'target': self.target,
                'type': 'summary',
            },
            *self._result_records(),
        ]
        return ''.join(json.dumps(record, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n' for record in records)

    def _result_records(self) -> list[dict[str, object]]:
        sources_by_result: dict[tuple[ResultKind, str], list[str]] = {}
        for observation in self.observations:
            sources_by_result.setdefault((observation.kind, observation.value), []).append(observation.source)
        return [
            {'type': kind, 'value': value, 'sources': sources_by_result.get((kind, value), [])} for kind, value in self.results
        ]
