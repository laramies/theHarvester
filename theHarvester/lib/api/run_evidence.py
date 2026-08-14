from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from theHarvester.lib.asn_attribution import asn_attribution_details, parse_asn_attribution_details
from theHarvester.lib.completed_result import parse_result_jsonl, parse_virtual_host_details, virtual_host_details
from theHarvester.lib.evidence_types import EVIDENCE_STATUSES
from theHarvester.lib.network_evidence import (
    network_observation_details,
    parse_network_observation_details,
)
from theHarvester.lib.result_values import normalize_prefix
from theHarvester.lib.shodan_evidence import ShodanHostObservation

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
        'results': [dict(record) for record in findings],
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
    for result in evidence['results']:
        if not isinstance(result, dict):
            continue
        if result.get('type') == 'vhost':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='vhost is not a result type; use hostname with virtual-host observations',
            )
        if result.get('type') == 'shodan-host':
            allowed_keys = {'type', 'value', 'sources', 'actions', 'details'}
            if set(result) - allowed_keys:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Shodan host evidence contains unsupported fields',
                )
            sources = result.get('sources', [])
            actions = result.get('actions', [])
            if (
                not isinstance(sources, list)
                or any(not isinstance(source, str) or not source.strip() for source in sources)
                or not isinstance(actions, list)
                or any(not isinstance(action, str) or not action.strip() for action in actions)
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Shodan host producers must be arrays of non-empty strings',
                )
            value = result.get('value')
            if not isinstance(value, str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Shodan host evidence must identify a canonical IP address',
                )
            try:
                shodan_host = ShodanHostObservation.from_record(value, result.get('details'))
                if shodan_host.ip != value or shodan_host.to_details() != result.get('details'):
                    raise ValueError('Shodan host evidence must use canonical structured details')
            except ValueError as error:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
            result['sources'] = sorted(set(sources))
            result['actions'] = sorted(set(actions))
            result['details'] = shodan_host.to_details()
            continue
        if result.get('type') == 'prefix':
            allowed_keys = {'type', 'value', 'sources', 'actions', 'scope', 'observations'}
            if set(result) - allowed_keys:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Network evidence contains unsupported fields',
                )
            result_value = result.get('value')
            if not isinstance(result_value, str) or result.get('scope') != 'external-relationship':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Network evidence requires a canonical prefix with external-relationship scope',
                )
            sources = result.get('sources', [])
            actions = result.get('actions', [])
            if (
                not isinstance(sources, list)
                or any(not isinstance(source, str) or not source.strip() for source in sources)
                or not isinstance(actions, list)
                or any(not isinstance(action, str) or not action.strip() for action in actions)
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Network evidence producers must be arrays of non-empty strings',
                )
            try:
                if normalize_prefix(result_value) != result_value:
                    raise ValueError('network evidence result value must be a canonical prefix')
                if 'observations' in result:
                    network_observations = parse_network_observation_details(result_value, result.get('observations'))
                    result['observations'] = network_observation_details(network_observations)
            except ValueError as error:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
            result['sources'] = sorted(set(sources))
            result['actions'] = sorted(set(actions))
            continue
        if result.get('type') == 'asn' and 'observations' in result:
            allowed_keys = {'type', 'value', 'sources', 'actions', 'observations'}
            if set(result) - allowed_keys:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='ASN attribution contains unsupported fields',
                )
            result_value = result.get('value')
            if not isinstance(result_value, str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='ASN attribution must identify a canonical ASN',
                )
            try:
                attributions = parse_asn_attribution_details(result_value, result.get('observations'))
            except ValueError as error:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
            result['observations'] = asn_attribution_details(attributions)
            continue
        if 'observations' not in result:
            continue
        if result.get('type') != 'hostname':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host observations belong to hostname findings',
            )
        allowed_keys = {'type', 'value', 'sources', 'actions', 'observations'}
        if set(result) - allowed_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host evidence contains unsupported fields',
            )
        sources = result.get('sources', [])
        actions = result.get('actions', [])
        if (
            not isinstance(sources, list)
            or any(not isinstance(source, str) or not source.strip() for source in sources)
            or not isinstance(actions, list)
            or any(not isinstance(action, str) or not action.strip() for action in actions)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host producers must be arrays of non-empty strings',
            )
        details = result.get('observations')
        if not isinstance(details, list) or not details:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host evidence requires structured observations',
            )
        result_value = result.get('value')
        if not isinstance(result_value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host evidence must identify a hostname',
            )
        try:
            vhost_observations = parse_virtual_host_details(result_value, details)
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
        target = str(evidence['target'])
        try:
            ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host evidence requires a hostname target scope',
            )
        if any(
            observation.hostname == target or not observation.hostname.endswith(f'.{target}')
            for observation in vhost_observations
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Virtual-host evidence must be a strict descendant of the run target',
            )
        result['sources'] = sorted(set(sources))
        result['actions'] = sorted(set(actions))
        result['observations'] = virtual_host_details(vhost_observations)
    return evidence
