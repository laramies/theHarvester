import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Self, get_args
from uuid import UUID, uuid4

ResultKind = Literal[
    'analytics',
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
    'twitter-person',
    'url',
    'vhost',
]

SCHEMA_VERSION = 'theharvester-results-v1'
RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


@dataclass(frozen=True, slots=True)
class CompletedResult:
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    results: tuple[tuple[ResultKind, str], ...]

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
        )

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
            *({'type': kind, 'value': value} for kind, value in self.results),
        ]
        return ''.join(json.dumps(record, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n' for record in records)
