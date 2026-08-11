import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from theHarvester.lib.active_evidence import ActionExecution, ActionObservation, ActiveEvidence, ArtifactReference
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution, parse_result_jsonl
from theHarvester.lib.virtual_host import VirtualHostObservation


def vhost_observation(
    endpoint: str,
    *,
    status: int,
    control_status: int,
    hostname: str = 'admin.example.com',
) -> VirtualHostObservation:
    return VirtualHostObservation.from_record(
        {
            'type': 'vhost',
            'endpoint': endpoint,
            'hostname': hostname,
            'http_host': hostname,
            'tls_server_name': None,
            'classification': 'distinct',
            'phase': 'body',
            'status': status,
            'location': None,
            'body_sha256': 'a' * 64,
            'body_size': 5,
            'body_truncated': False,
            'context_phase': 'body',
            'context_status': control_status,
            'context_location': None,
            'context_body_sha256': 'a' * 64,
            'context_body_size': 5,
            'context_body_truncated': False,
            'control_phase': 'body',
            'control_status': control_status,
            'control_location': None,
            'control_body_sha256': 'a' * 64,
            'control_body_size': 5,
            'control_body_truncated': False,
            'confirmation_body_sha256': None,
            'tls_verified': None,
            'distinct_signals': ['status'],
            'reflection_normalized': False,
        }
    )


@pytest.mark.parametrize('evidence_status', ['partial', 'failed'])
def test_sparse_completed_result_retains_explicit_status(evidence_status: str) -> None:
    result = CompletedResult.finish(
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={},
        evidence_status=evidence_status,
    )

    assert result.status == evidence_status
    assert json.loads(result.jsonl().splitlines()[0])['evidence_status'] == evidence_status


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
                    groups={'ip': ['192.0.2.10']},
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

    assert result.results == (('hostname', 'api.example.com'), ('ip', '192.0.2.10'))
    assert result.active_evidence.executions[0].observations == (ActionObservation('ip', '192.0.2.10'),)
    assert result.active_evidence.executions[1].artifacts == (artifact,)
    assert not any(kind == 'screenshot' for kind, _value in result.results)
    assert result.evidence_dict()['results'] == [
        {'type': 'hostname', 'value': 'api.example.com', 'sources': []},
        {'type': 'ip', 'value': '192.0.2.10', 'sources': [], 'actions': ['dns-resolve']},
    ]
    assert [json.loads(line) for line in result.jsonl().splitlines()][1:] == [
        {'type': 'hostname', 'value': 'api.example.com', 'sources': []},
        {'type': 'ip', 'value': '192.0.2.10', 'sources': [], 'actions': ['dns-resolve']},
    ]


def test_completed_result_groups_structured_vhost_evidence_by_hostname() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    first = vhost_observation('http://192.0.2.10', status=200, control_status=404)
    second = vhost_observation('http://192.0.2.11', status=201, control_status=404)
    result = CompletedResult.finish(
        target='example.com',
        started_at=completed_at,
        completed_at=completed_at,
        groups={'hostname': ['admin.example.com']},
        source_executions=(SourceExecution('crtsh', 'completed', 4.0, 1),),
        observations=(ResultObservation('crtsh', 'hostname', 'admin.example.com'),),
        active_evidence=ActiveEvidence(
            executions=(
                ActionExecution.finish(
                    action='vhost',
                    status='completed',
                    duration_ms=12.5,
                    groups={'hostname': ['admin.example.com', 'admin.example.com']},
                ),
            )
        ),
        virtual_hosts=(second, first, first),
    )

    records = [json.loads(line) for line in result.jsonl().splitlines()]
    _summary, parsed_findings = parse_result_jsonl(result.jsonl())

    assert result.virtual_hosts == (first, second)
    assert result.results == (('hostname', 'admin.example.com'),)
    assert result.active_evidence.executions[0].result_count == 1
    assert records[0]['counts'] == {'hostname': 1}
    assert records[0]['result_count'] == 1
    assert records[1] == {
        'type': 'hostname',
        'value': 'admin.example.com',
        'sources': ['crtsh'],
        'actions': ['vhost'],
        'observations': [
            {key: value for key, value in observation.to_record().items() if key not in {'type', 'hostname'}}
            for observation in (first, second)
        ],
    }
    assert parsed_findings == records[1:]


def test_completed_result_rejects_structured_vhost_without_vhost_action_provenance() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='vhost action'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={'hostname': ['admin.example.com']},
            virtual_hosts=(vhost_observation('http://192.0.2.10', status=200, control_status=404),),
        )


def test_completed_result_rejects_unstructured_vhost_action_result() -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='structured virtual-host evidence'):
        CompletedResult.finish(
            target='example.com',
            started_at=completed_at,
            completed_at=completed_at,
            groups={},
            active_evidence=ActiveEvidence(
                executions=(
                    ActionExecution.finish(
                        action='vhost',
                        status='completed',
                        duration_ms=1,
                        groups={'hostname': ['admin.example.com']},
                    ),
                )
            ),
        )


@pytest.mark.parametrize(
    ('target', 'hostname'),
    [
        ('example.com', 'example.com'),
        ('example.com', 'admin.other.test'),
        ('192.0.2.8', 'admin.192.0.2.8'),
    ],
)
def test_completed_result_rejects_structured_vhost_outside_the_run_scope(target: str, hostname: str) -> None:
    completed_at = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match='run target scope'):
        CompletedResult.finish(
            target=target,
            started_at=completed_at,
            completed_at=completed_at,
            groups={},
            active_evidence=ActiveEvidence(
                executions=(
                    ActionExecution.finish(
                        action='vhost',
                        status='completed',
                        duration_ms=1,
                        groups={'hostname': [hostname]},
                    ),
                )
            ),
            virtual_hosts=(
                vhost_observation(
                    'http://192.0.2.10',
                    status=200,
                    control_status=404,
                    hostname=hostname,
                ),
            ),
        )


def test_jsonl_rejects_noncanonical_structured_vhost_hostname() -> None:
    observation = vhost_observation('http://192.0.2.10', status=200, control_status=404)
    details = {key: value for key, value in observation.to_record().items() if key not in {'type', 'hostname'}}
    payload = '\n'.join(
        (
            json.dumps({'type': 'summary'}),
            json.dumps(
                {
                    'type': 'hostname',
                    'value': 'Admin.Example.com',
                    'sources': [],
                    'actions': ['vhost'],
                    'observations': [details],
                }
            ),
        )
    )

    with pytest.raises(ValueError, match='canonical hostname'):
        parse_result_jsonl(payload)


def test_jsonl_rejects_legacy_vhost_result_kind() -> None:
    payload = '\n'.join(
        (
            json.dumps({'type': 'summary'}),
            json.dumps(
                {
                    'type': 'vhost',
                    'value': 'admin.example.com',
                    'sources': [],
                    'actions': ['vhost'],
                }
            ),
        )
    )

    with pytest.raises(ValueError, match='known type'):
        parse_result_jsonl(payload)


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
