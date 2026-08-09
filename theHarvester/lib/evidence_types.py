from datetime import UTC, datetime
from typing import Literal, get_args

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

RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))
EXECUTION_STATUSES: frozenset[str] = frozenset(get_args(ExecutionStatus))


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')
