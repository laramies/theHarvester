from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from theHarvester.lib.completed_result import parse_result_jsonl
from theHarvester.lib.evidence_types import EVIDENCE_STATUSES

from .run_models import _normalize_target


def parse_jsonl_import(body: bytes) -> dict[str, Any]:
    try:
        summary, findings = parse_result_jsonl(body)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    try:
        raw_run_id = summary.get('run_id')
        if not isinstance(raw_run_id, str):
            raise ValueError
        run_id = str(UUID(raw_run_id))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='JSONL summary must contain a UUID run_id',
        ) from error
    timestamps: dict[str, datetime] = {}
    for field in ('started_at', 'completed_at'):
        value = summary.get(field)
        try:
            timestamp = datetime.fromisoformat(value) if isinstance(value, str) else None
        except ValueError:
            timestamp = None
        if timestamp is None or timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'JSONL summary must contain an ISO-8601 UTC {field}',
            )
        timestamps[field] = timestamp
    if timestamps['completed_at'] < timestamps['started_at']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='JSONL summary completed_at must not be earlier than started_at',
        )
    evidence = {
        'run_id': run_id,
        'target': summary.get('target'),
        'status': summary.get('evidence_status'),
        'started_at': summary.get('started_at'),
        'completed_at': summary.get('completed_at'),
        'results': [
            {
                'type': record['type'],
                'value': record['value'],
                'sources': record['sources'],
                'actions': record['actions'],
            }
            for record in findings
        ],
        'source_executions': summary.get('source_executions', []),
        'action_executions': summary.get('action_executions', []),
        'artifacts': summary.get('artifacts', []),
    }
    return validate_evidence(evidence)


def validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not evidence.get('target'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file does not identify a target')
    try:
        evidence['target'] = _normalize_target(str(evidence['target']))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    if evidence.get('status') not in EVIDENCE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Evidence status must be complete, partial, or failed',
        )
    for field in ('started_at', 'completed_at'):
        value = evidence.get(field)
        if value is not None and not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Evidence field {field} must be a string',
            )
    for field in ('results', 'source_executions', 'action_executions', 'artifacts'):
        value = evidence.get(field)
        if value is None:
            evidence[field] = []
        elif not isinstance(value, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Evidence field {field} must be an array',
            )
    return evidence
