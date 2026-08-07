from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException, status

from theHarvester.lib.completed_result import SCHEMA_VERSION as RESULTS_SCHEMA_VERSION
from theHarvester.lib.source_catalog import ACTION_ACTIVITIES, SOURCE_SPECS, ActivityClass, SourceSpec, get_source_spec

from .run_models import _normalize_target, default_database_path, utc_now

LEGACY_RESULT_ROUTES = {
    'hosts': 'subdomain',
    'ips': 'ip',
    'emails': 'email',
    'asns': 'asn',
    'interesting_urls': 'interesting-url',
    'trello_urls': 'url',
    'twitter_people': 'twitter-person',
    'linkedin_people': 'linkedin-person',
    'linkedin_links': 'linkedin-link',
    'people': 'person',
    'vhosts': 'vhost',
    'shodan': 'shodan',
    'takeover_results': 'takeover',
}
RESULT_TYPE_ALIASES = {'hostname': 'subdomain', 'ip-address': 'ip'}


def _activities(request: dict[str, Any]) -> list[str]:
    if request.get('activities'):
        return list(request['activities'])
    activities = {'P0'}
    source_activities = {_source.activity for source in request.get('sources', []) if (_source := _source_spec(source))}
    if ActivityClass.DNS in source_activities:
        activities.add('P1')
    if ActivityClass.DIRECT in source_activities:
        activities.add('P2')
    if (
        request.get('dns_brute')
        or request.get('dns_lookup')
        or request.get('dns_resolve')
        or request.get('dns_recursive_depth', 0) > 0
    ):
        activities.add('P1')
    if request.get('screenshot') or request.get('take_over') or request.get('api_scan'):
        activities.add('P2')
    return [activity for activity in ('P0', 'P1', 'P2') if activity in activities]


def _source_spec(name: str) -> SourceSpec | None:
    try:
        return get_source_spec(name)
    except KeyError:
        return None


def _results(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(result_type: str, value: object, dns_status: str | None = None) -> None:
        if value is None or value == '':
            return
        normalized_value = str(value)
        key = (result_type, normalized_value)
        if key in seen:
            return
        seen.add(key)
        item: dict[str, Any] = {'type': result_type, 'value': normalized_value}
        if dns_status is not None:
            item['dns_status'] = dns_status
        results.append(item)

    for item in evidence.get('results') or []:
        if isinstance(item, dict) and item.get('type') != 'screenshot':
            result_type = str(item.get('type', 'other'))
            add(
                RESULT_TYPE_ALIASES.get(result_type, result_type),
                item.get('value'),
                item.get('dns_status'),
            )

    for entity in evidence.get('entities') or []:
        if not isinstance(entity, dict):
            continue
        scope_classes = entity.get('scope_classes', [])
        result_type = 'subdomain'
        if 'scope-extension' in scope_classes:
            result_type = 'scope-extension'
        elif 'external-relationship' in scope_classes:
            result_type = 'external-relationship'
        addressability = entity.get('addressability')
        dns_status = (
            {
                'currently-addressable': 'resolved',
                'not-currently-addressable': 'no-answer',
                'resolver-disputed': 'disputed',
                'wildcard-uncertain': 'uncertain',
                'unverified': 'not-captured',
            }.get(str(addressability))
            if addressability is not None
            else None
        )
        add(result_type, entity.get('value'), dns_status)

    kind_map = {
        **RESULT_TYPE_ALIASES,
        'interesting-url': 'interesting-url',
        'api-endpoint': 'api-endpoint',
        'shodan-result': 'shodan',
    }
    for observation in evidence.get('selected_observations') or []:
        if not isinstance(observation, dict) or observation.get('kind') == 'screenshot':
            continue
        kind = str(observation.get('kind', 'other'))
        add(kind_map.get(kind, kind), observation.get('value'))

    legacy = evidence.get('_legacy', {})
    if not isinstance(legacy, dict):
        legacy = {}
    for key, result_type in LEGACY_RESULT_ROUTES.items():
        for value in legacy.get(key, []):
            add(result_type, json.dumps(value, sort_keys=True) if isinstance(value, dict) else value)
    return results


def _source_executions(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    executions = evidence.get('source_executions') or evidence.get('executions') or []
    return [dict(execution) for execution in executions if isinstance(execution, dict)]


def _screenshots(_evidence: dict[str, Any] | None, run_id: str) -> list[dict[str, Any]]:
    screenshot_dir = _artifact_dir(run_id) / 'screenshots'
    if not screenshot_dir.is_dir():
        return []
    return [
        {
            'name': path.name,
            'target': path.stem,
            'url': f'/api/v1/runs/{run_id}/screenshots/{path.name}',
        }
        for path in sorted(screenshot_dir.glob('*.png'))
        if path.is_file()
    ]


def _evidence_activities(executions: list[dict[str, Any]]) -> list[str]:
    activities: set[str] = set()
    source_activities = {source.name: source.activity.value for source in SOURCE_SPECS.values()}
    for execution in executions:
        source = str(execution.get('source') or execution.get('name') or '')
        activity = str(execution.get('activity') or '')
        declared = source_activities.get(source)
        if source.startswith('action:'):
            declared = ACTION_ACTIVITIES.get(source.removeprefix('action:'))
        if declared:
            activities.add(str(declared))
        elif activity in {'P0', 'P1', 'P2'}:
            activities.add(activity)
    if not activities:
        activities.add('P0')
    return [activity for activity in ('P0', 'P1', 'P2') if activity in activities]


def _legacy_target(payload: dict[str, Any]) -> str | None:
    command = payload.get('cmd')
    if not isinstance(command, str):
        return None
    try:
        arguments = shlex.split(command)
    except ValueError:
        return None
    for flag in ('-d', '--domain'):
        if flag in arguments and arguments.index(flag) + 1 < len(arguments):
            return arguments[arguments.index(flag) + 1]
    return None


def _parse_json_import(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file is not valid JSON') from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result JSON must be an object')
    if isinstance(payload.get('evidence_run'), dict):
        evidence = dict(payload['evidence_run'])
        evidence['_legacy'] = {key: value for key, value in payload.items() if key != 'evidence_run'}
    elif isinstance(payload.get('run'), dict):
        evidence = dict(payload['run'])
        evidence['_legacy'] = {key: value for key, value in payload.items() if key != 'run'}
    else:
        evidence = dict(payload)
        if 'target' not in evidence:
            evidence = {
                'run_id': str(uuid4()),
                'target': _legacy_target(payload),
                'status': 'complete',
                'started_at': None,
                'completed_at': utc_now(),
                '_legacy': payload,
            }
    return _validate_evidence(evidence)


def _parse_jsonl_import(body: bytes) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    try:
        for line in body.decode('utf-8').splitlines():
            if line.strip():
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError
                records.append(record)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file is not valid JSONL') from error
    summary = records[0] if records else None
    if not summary or summary.get('schema_version') != RESULTS_SCHEMA_VERSION or summary.get('type') != 'summary':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'JSONL must use {RESULTS_SCHEMA_VERSION}',
        )
    findings = records[1:]
    if any(
        not isinstance(record.get('type'), str)
        or not record['type'].strip()
        or record['type'] == 'summary'
        or not isinstance(record.get('value'), str)
        or not record['value'].strip()
        for record in findings
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='JSONL findings must contain type and value')
    evidence = {
        'run_id': summary.get('run_id'),
        'target': summary.get('target'),
        'status': 'partial',
        'started_at': summary.get('started_at'),
        'completed_at': summary.get('completed_at'),
        'results': [{'type': record['type'], 'value': record['value'], 'sources': []} for record in findings],
        'source_executions': [],
    }
    return _validate_evidence(evidence)


def _validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not evidence.get('target'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file does not identify a target')
    try:
        evidence['target'] = _normalize_target(str(evidence['target']))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    if evidence.get('status') not in {'complete', 'partial', 'failed'}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Evidence status must be complete, partial, or failed',
        )
    for field in ('results', 'source_executions', 'executions', 'entities', 'selected_observations'):
        value = evidence.get(field)
        if value is None:
            evidence[field] = []
        elif not isinstance(value, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Evidence field {field} must be an array',
            )
    for entity in evidence['entities']:
        if not isinstance(entity, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Evidence entities must be objects')
        for field in ('scope_classes', 'observations', 'provenance'):
            if field in entity and not isinstance(entity[field], list):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'Evidence entity field {field} must be an array',
                )
    legacy = evidence.get('_legacy')
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Evidence field _legacy must be an object')
        for field in LEGACY_RESULT_ROUTES:
            if field in legacy and not isinstance(legacy[field], list):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'Legacy evidence field {field} must be an array',
                )
    evidence.setdefault('run_id', str(uuid4()))
    evidence.setdefault('completed_at', utc_now())
    return evidence


def _artifact_dir(run_id: str, *, database: Path | None = None) -> Path:
    configured = os.getenv('THEHARVESTER_RUN_ARTIFACTS')
    root = Path(configured) if configured else (database or default_database_path()).parent / 'run-artifacts'
    return root / run_id


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise OSError(f'Refusing symlinked theHarvester directory: {path}')
    path.chmod(0o700)


def _read_child_evidence(artifact_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    evidence_path = artifact_dir / 'evidence.json'
    if not evidence_path.is_file():
        return None, None
    try:
        return _validate_evidence(json.loads(evidence_path.read_text(encoding='utf-8'))), None
    except (OSError, json.JSONDecodeError, HTTPException) as error:
        return None, f'Child evidence is invalid: {error}'


def _write_child_evidence(artifact_dir: Path, evidence: Any, *, partial: bool) -> None:
    payload = evidence.evidence_dict()
    if partial:
        payload['status'] = 'partial'
    temporary = artifact_dir / 'evidence.json.tmp'
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.chmod(0o600)
    evidence_path = artifact_dir / 'evidence.json'
    temporary.replace(evidence_path)
    evidence_path.chmod(0o600)
