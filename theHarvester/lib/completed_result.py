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
ExecutionStatus = Literal['succeeded', 'empty', 'failed', 'rate-limited', 'skipped']

SCHEMA_VERSION = 'theharvester-results-v1'
RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))
JSONL_RESULT_KINDS: frozenset[str] = RESULT_KINDS | {'external-relationship', 'other', 'scope-extension'}
EXECUTION_STATUSES: frozenset[str] = frozenset(get_args(ExecutionStatus))
DNS_STATUSES: frozenset[str] = frozenset({'resolved', 'no-answer', 'disputed', 'uncertain', 'not-captured'})


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def _validated_jsonl_findings(findings: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    records = [dict(finding) for finding in findings]
    if any(
        not isinstance(result_type := record.get('type'), str)
        or result_type not in JSONL_RESULT_KINDS
        or not isinstance(value := record.get('value'), str)
        or not value.strip()
        or (
            record.get('dns_status') is not None
            and (not isinstance(record['dns_status'], str) or record['dns_status'] not in DNS_STATUSES)
        )
        for record in records
    ):
        raise ValueError('JSONL findings must contain a known type and non-empty value')
    return records


def encode_result_jsonl(
    summary: Mapping[str, object],
    findings: Iterable[Mapping[str, object]],
) -> str:
    summary_record = {**summary, 'schema_version': SCHEMA_VERSION, 'type': 'summary'}
    records = [summary_record, *_validated_jsonl_findings(findings)]
    return ''.join(json.dumps(record, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n' for record in records)


def parse_result_jsonl(payload: bytes | str) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        text = payload.decode('utf-8') if isinstance(payload, bytes) else payload
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('result file is not valid JSONL') from error
    if any(not isinstance(record, dict) for record in records):
        raise ValueError('JSONL records must be objects')
    summary = records[0] if records else None
    if not summary or summary.get('schema_version') != SCHEMA_VERSION or summary.get('type') != 'summary':
        raise ValueError(f'JSONL must use {SCHEMA_VERSION}')
    return summary, _validated_jsonl_findings(records[1:])


@dataclass(frozen=True, slots=True)
class SourceExecution:
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
class CompletedResult:
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    results: tuple[tuple[ResultKind, str], ...]
    source_executions: tuple[SourceExecution, ...] = ()

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
        )

    def evidence_dict(self) -> dict[str, object]:
        incomplete = {'failed', 'rate-limited', 'skipped'}
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
            'results': [{'type': kind, 'value': value, 'sources': []} for kind, value in self.results],
            'source_executions': [execution.to_dict() for execution in self.source_executions],
        }

    def jsonl(self) -> str:
        counts = Counter(kind for kind, _value in self.results)
        return encode_result_jsonl(
            {
                'completed_at': _isoformat_utc(self.completed_at),
                'counts': dict(sorted(counts.items())),
                'result_count': len(self.results),
                'run_id': str(self.run_id),
                'started_at': _isoformat_utc(self.started_at),
                'target': self.target,
            },
            ({'type': kind, 'value': value} for kind, value in self.results),
        )
