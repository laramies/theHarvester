import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from theHarvester.lib.active_evidence import ActionExecution, ActionObservation, ActiveEvidence, ArtifactReference
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution


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
            'evidence_status': 'complete',
            'result_count': 3,
            'run_id': 'f047261c-0afb-4e18-89d5-28a7d977f51f',
            'source_executions': [],
            'action_executions': [],
            'artifacts': [],
            'started_at': '2026-08-05T12:00:00Z',
            'target': 'example.com',
            'type': 'summary',
        },
        {
            'sources': [],
            'type': 'email',
            'value': 'admin@example.com',
        },
        {
            'sources': [],
            'type': 'hostname',
            'value': 'api.example.com',
        },
        {
            'sources': [],
            'type': 'hostname',
            'value': 'www.example.com',
        },
    ]
    assert 'schema' not in records[0]
    assert 'schema_version' not in records[0]
    assert result.jsonl().endswith('\n')


def test_completed_result_exposes_truthful_source_execution_evidence() -> None:
    started_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    result = CompletedResult.finish(
        target='example.com',
        started_at=started_at,
        completed_at=started_at,
        groups={'hostname': ['www.example.com']},
        source_executions=(
            SourceExecution('crtsh', 'completed', 12.5, 1),
            SourceExecution('builtwith', 'partial', 0, 0, stop_reason='invalid-response'),
        ),
        observations=(ResultObservation('crtsh', 'hostname', 'www.example.com'),),
    )

    evidence = result.evidence_dict()

    assert evidence['status'] == 'partial'
    assert evidence['source_executions'] == [
        {
            'source': 'crtsh',
            'status': 'completed',
            'duration_ms': 12.5,
            'result_count': 1,
            'error_type': None,
            'stop_reason': None,
        },
        {
            'source': 'builtwith',
            'status': 'partial',
            'duration_ms': 0,
            'result_count': 0,
            'error_type': None,
            'stop_reason': 'invalid-response',
        },
    ]


def test_completed_result_attributes_each_finding_to_its_sources() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    result = CompletedResult.finish(
        target='example.com',
        started_at=completed_at,
        completed_at=completed_at,
        groups={'hostname': ['api.example.com', 'mail.example.com']},
        source_executions=(
            SourceExecution('crtsh', 'completed', 12.5, 2),
            SourceExecution('certspotter', 'completed', 8.0, 1),
        ),
        observations=(
            ResultObservation('crtsh', 'hostname', 'api.example.com'),
            ResultObservation('certspotter', 'hostname', 'api.example.com'),
            ResultObservation('crtsh', 'hostname', 'mail.example.com'),
        ),
    )

    records = [json.loads(line) for line in result.jsonl().splitlines()]

    assert records[1:] == [
        {
            'sources': ['certspotter', 'crtsh'],
            'type': 'hostname',
            'value': 'api.example.com',
        },
        {
            'sources': ['crtsh'],
            'type': 'hostname',
            'value': 'mail.example.com',
        },
    ]
    assert result.evidence_dict()['results'] == records[1:]


def test_completed_result_rejects_observation_without_execution() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='matching source execution'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={'hostname': ['api.example.com']},
            observations=(ResultObservation('crtsh', 'hostname', 'api.example.com'),),
        )


def test_completed_result_rejects_duplicate_source_executions() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='source executions must be unique'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={},
            source_executions=(
                SourceExecution('crtsh', 'completed', 1.0, 0),
                SourceExecution('crtsh', 'failed', 2.0, 0, error_type='RuntimeError'),
            ),
        )


def test_completed_result_rejects_source_count_without_matching_origins() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='result count must match'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={'hostname': ['api.example.com']},
            source_executions=(SourceExecution('crtsh', 'completed', 1.0, 1),),
        )


def test_completed_result_merges_active_results_and_keeps_screenshot_as_an_artifact() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    artifact = ArtifactReference(
        kind='screenshot',
        subject_kind='hostname',
        subject_value='api.example.com',
        path='screenshots/api.example.com.png',
        media_type='image/png',
        size_bytes=3,
        sha256='0' * 64,
        created_at=completed_at,
    )
    result = CompletedResult.finish(
        target='example.com',
        started_at=completed_at,
        completed_at=completed_at,
        groups={'hostname': ['api.example.com']},
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='dns-resolve',
                    status='completed',
                    duration_ms=12.5,
                    groups={'ip-address': ['192.0.2.10']},
                ),
                ActionExecution.finish(
                    action='screenshot',
                    status='completed',
                    duration_ms=4.0,
                    groups={},
                    artifacts=(artifact,),
                ),
            )
        ),
    )

    assert result.results == (('hostname', 'api.example.com'), ('ip-address', '192.0.2.10'))
    assert result.active_evidence.executions[0].observations == (ActionObservation('ip-address', '192.0.2.10'),)
    assert result.active_evidence.executions[1].artifacts == (artifact,)
    assert not any(kind == 'screenshot' for kind, _value in result.results)
    assert result.evidence_dict()['results'] == [
        {'type': 'hostname', 'value': 'api.example.com', 'sources': []},
        {'type': 'ip-address', 'value': '192.0.2.10', 'sources': [], 'actions': ['dns-resolve']},
    ]
    assert [json.loads(line) for line in result.jsonl().splitlines()][1:] == [
        {'type': 'hostname', 'value': 'api.example.com', 'sources': []},
        {'type': 'ip-address', 'value': '192.0.2.10', 'sources': [], 'actions': ['dns-resolve']},
    ]


def test_completed_result_rejects_artifact_without_a_real_subject_result() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    artifact = ArtifactReference(
        kind='screenshot',
        subject_kind='hostname',
        subject_value='missing.example.com',
        path='screenshots/missing.example.com.png',
        media_type='image/png',
        size_bytes=3,
        sha256='0' * 64,
        created_at=completed_at,
    )

    with pytest.raises(ValueError, match='artifact must reference a completed result'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={},
            active_evidence=ActiveEvidence(
                executions=(
                    ActionExecution.finish(
                        action='screenshot',
                        status='completed',
                        duration_ms=4.0,
                        groups={},
                        artifacts=(artifact,),
                    ),
                )
            ),
        )


def test_action_status_contributes_to_completed_result_status() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    result = CompletedResult.finish(
        target='example.com',
        started_at=completed_at,
        completed_at=completed_at,
        groups={},
        source_executions=(SourceExecution('crtsh', 'completed', 1.0, 0),),
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='takeover',
                    status='failed',
                    duration_ms=2.0,
                    groups={},
                    error_type='RuntimeError',
                ),
            )
        ),
    )

    assert result.evidence_dict()['status'] == 'partial'


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
