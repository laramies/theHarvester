from datetime import UTC, datetime

import pytest

from theHarvester.lib.active_evidence import ActionExecution, ActionObservation, ActiveEvidence, ArtifactReference


def screenshot_artifact() -> ArtifactReference:
    return ArtifactReference(
        kind='screenshot',
        subject_kind='hostname',
        subject_value='api.example.com',
        path='screenshots/api.example.com.png',
        media_type='image/png',
        size_bytes=3,
        sha256='0' * 64,
        created_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
    )


def test_active_evidence_owns_action_results_and_artifacts() -> None:
    evidence = ActiveEvidence(
        executions=(
            ActionExecution.finish(
                action='dns-resolve',
                status='completed',
                duration_ms=12.5,
                groups={'ip-address': ['192.0.2.10', '192.0.2.10']},
            ),
            ActionExecution.finish(
                action='screenshot',
                status='completed',
                duration_ms=4.0,
                groups={},
                artifacts=(screenshot_artifact(),),
            ),
            ActionExecution.finish(action='takeover', status='completed', duration_ms=2.0, groups={}),
        )
    )

    assert evidence.executions[0].result_count == 1
    assert evidence.executions[0].observations == (ActionObservation('ip-address', '192.0.2.10'),)
    assert evidence.executions[1].result_count == 0
    assert evidence.executions[1].artifacts == (screenshot_artifact(),)


def test_active_evidence_rejects_duplicate_actions() -> None:
    with pytest.raises(ValueError, match='action executions must be unique'):
        ActiveEvidence(
            executions=(
                ActionExecution('dns-resolve', 'completed', 1.0),
                ActionExecution('dns-resolve', 'failed', 2.0, error_type='RuntimeError'),
            )
        )


def test_action_execution_rejects_noncanonical_observations_and_artifacts() -> None:
    observation = ActionObservation('hostname', 'api.example.com')
    artifact = screenshot_artifact()

    with pytest.raises(ValueError, match='action observations must be deduplicated and sorted'):
        ActionExecution('dns-brute', 'completed', 1.0, observations=(observation, observation))
    with pytest.raises(ValueError, match='artifacts must be deduplicated and sorted'):
        ActionExecution('screenshot', 'completed', 1.0, artifacts=(artifact, artifact))


def test_active_evidence_rejects_screenshot_results() -> None:
    with pytest.raises(ValueError, match='screenshots must be stored as artifacts'):
        ActionExecution.finish(
            action='screenshot',
            status='completed',
            duration_ms=1.0,
            groups={'screenshot': ['https://api.example.com']},
        )
    with pytest.raises(ValueError, match='known non-empty result'):
        ArtifactReference(
            kind='screenshot',
            subject_kind='screenshot',
            subject_value='https://api.example.com',
            path='screenshots/api.example.com.png',
            media_type='image/png',
            size_bytes=3,
            sha256='0' * 64,
            created_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        )


def test_artifact_reference_rejects_invalid_metadata() -> None:
    with pytest.raises(ValueError, match='sha256'):
        ArtifactReference(
            kind='screenshot',
            subject_kind='hostname',
            subject_value='api.example.com',
            path='screenshots/api.example.com.png',
            media_type='image/png',
            size_bytes=3,
            sha256='not-a-hash',
            created_at=datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match='timezone-aware'):
        ArtifactReference(
            kind='screenshot',
            subject_kind='hostname',
            subject_value='api.example.com',
            path='screenshots/api.example.com.png',
            media_type='image/png',
            size_bytes=3,
            sha256='0' * 64,
            created_at=datetime(2026, 8, 9, 12, 0),
        )
