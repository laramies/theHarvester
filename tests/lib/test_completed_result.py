import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from theHarvester.lib.completed_result import CompletedResult


def test_completed_result_is_deterministic_and_deduplicated() -> None:
    result = CompletedResult.finish(
        run_id=UUID('f047261c-0afb-4e18-89d5-28a7d977f51f'),
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={
            'hostname': ['www.example.com', 'api.example.com', 'api.example.com'],
            'email': ['admin@example.com'],
        },
    )

    records = [json.loads(line) for line in result.jsonl().splitlines()]

    assert records == [
        {
            'completed_at': '2026-08-05T12:01:00Z',
            'counts': {'email': 1, 'hostname': 2},
            'result_count': 3,
            'run_id': 'f047261c-0afb-4e18-89d5-28a7d977f51f',
            'schema_version': 'theharvester-results-v1',
            'started_at': '2026-08-05T12:00:00Z',
            'target': 'example.com',
            'type': 'summary',
        },
        {
            'type': 'email',
            'value': 'admin@example.com',
        },
        {
            'type': 'hostname',
            'value': 'api.example.com',
        },
        {
            'type': 'hostname',
            'value': 'www.example.com',
        },
    ]
    assert result.jsonl().endswith('\n')


@pytest.mark.parametrize('value', ['', '   ', 7])
def test_completed_result_rejects_invalid_findings(value: Any) -> None:
    with pytest.raises(ValueError, match='non-empty string'):
        CompletedResult.finish(
            target='example.com',
            started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
            groups={'hostname': [value]},
        )


def test_completed_result_rejects_invalid_completion() -> None:
    started_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match='target'):
        CompletedResult.finish(
            target=' ',
            started_at=started_at,
            completed_at=started_at,
            groups={},
        )
    with pytest.raises(ValueError, match='timezone-aware'):
        CompletedResult.finish(
            target='example.com',
            started_at=datetime(2026, 8, 5, 12, 0),
            completed_at=started_at,
            groups={},
        )
    with pytest.raises(ValueError, match='earlier'):
        CompletedResult.finish(
            target='example.com',
            started_at=started_at,
            completed_at=datetime(2026, 8, 5, 11, 59, tzinfo=UTC),
            groups={},
        )


def test_completed_result_rejects_unknown_kind() -> None:
    groups: Any = {'source-status': ['complete']}

    with pytest.raises(ValueError, match='unknown result kind'):
        CompletedResult.finish(
            target='example.com',
            started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
            groups=groups,
        )


def test_completed_result_rejects_direct_whitespace_finding() -> None:
    with pytest.raises(ValueError, match='non-empty string'):
        CompletedResult(
            run_id=UUID('f047261c-0afb-4e18-89d5-28a7d977f51f'),
            target='example.com',
            started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
            results=(('hostname', ' '),),
        )
