from datetime import UTC, datetime
from uuid import UUID

from theHarvester.lib.hostname_comparison import (
    ComparableRunEvidence,
    ComparisonSourceOutcome,
    _difference_row,
    _run_indexes,
)


def test_difference_row_uses_run_indexes_for_hostname_evidence() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    previous = ComparableRunEvidence(
        run_id=UUID('f047261c-0afb-4e18-89d5-28a7d977f51f'),
        target='example.com',
        completed_at=completed_at,
        source_outcomes=(ComparisonSourceOutcome('crtsh', 'completed', None, None),),
        hostname_sources=(('api.example.com', ('crtsh',)),),
        resolved_hostnames=frozenset({'api.example.com'}),
        dns_action_status='completed',
        addressability=(('api.example.com', 'addressable'),),
    )
    current = ComparableRunEvidence(
        run_id=UUID('d88125d2-70dc-4bb2-9321-b14ef7326e83'),
        target='example.com',
        completed_at=completed_at,
        source_outcomes=(ComparisonSourceOutcome('crtsh', 'completed', None, None),),
        hostname_sources=(),
        resolved_hostnames=frozenset(),
        dns_action_status='completed',
        addressability=(),
    )

    difference, row = _difference_row(current, previous, 'api.example.com', _run_indexes(previous), _run_indexes(current))

    assert difference == 'no_longer_reported'
    assert row['sources_in_previous_run'] == ['crtsh']
    assert row['sources_in_current_run'] == []
    assert row['previous_resolution_evidence'] == 'positive'
    assert row['current_resolution_evidence'] == 'not-checked'
    assert row['previous_addressability'] == 'addressable'
    assert row['current_addressability'] is None
