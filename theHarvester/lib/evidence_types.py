from datetime import UTC, datetime
from typing import Literal, get_args

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
    'ip',
    'language',
    'linkedin-person',
    'person',
    'prefix',
    'server',
    'screenshot',
    'shodan-host',
    'takeover',
    'twitter-person',
    'url',
]
ExecutionStatus = Literal['completed', 'partial', 'failed', 'rate-limited', 'skipped']
EvidenceStatus = Literal['complete', 'partial', 'failed']

RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))
EXECUTION_STATUSES: frozenset[str] = frozenset(get_args(ExecutionStatus))
EVIDENCE_STATUSES: frozenset[str] = frozenset(get_args(EvidenceStatus))


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')
