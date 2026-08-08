from __future__ import annotations

from pathlib import Path
from typing import Any

from theHarvester.lib.source_catalog import ActivityClass, SourceSpec, activity_classes_for_selection, get_source_spec

RESULT_TYPE_ALIASES = {'hostname': 'subdomain', 'ip-address': 'ip'}
JSONL_RESULT_TYPE_ALIASES = {value: key for key, value in RESULT_TYPE_ALIASES.items()}


def activities_for_request(request: dict[str, Any]) -> list[str]:
    if request.get('activities'):
        return list(request['activities'])
    actions = [
        name
        for name in ('dns-brute', 'dns-lookup', 'dns-resolve', 'shodan', 'api-scan', 'screenshot', 'take-over')
        if request.get(name.replace('-', '_'))
    ]
    if request.get('dns_recursive_depth', 0) > 0:
        actions.append('dns-recursive')
    return [activity.value for activity in activity_classes_for_selection(request.get('sources', []), actions)]


def source_spec(name: str) -> SourceSpec | None:
    try:
        return get_source_spec(name)
    except KeyError:
        return None


def normalized_results(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
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
            add(RESULT_TYPE_ALIASES.get(result_type, result_type), item.get('value'), item.get('dns_status'))

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
                'wildcard-indistinguishable': 'uncertain',
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

    return results


def source_executions(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    executions = evidence.get('source_executions') or evidence.get('executions') or []
    return [dict(execution) for execution in executions if isinstance(execution, dict)]


def screenshots(evidence: dict[str, Any] | None, run_id: str, artifact_dir: Path) -> list[dict[str, Any]]:
    screenshot_dir = artifact_dir / 'screenshots'
    if not screenshot_dir.is_dir():
        return []
    allowed_names: set[str] = set()
    for item in (evidence or {}).get('results') or []:
        if not isinstance(item, dict) or item.get('type') != 'screenshot':
            continue
        name = f'{str(item.get("value", "")).removeprefix("https://").removeprefix("http://")}.png'
        if name and Path(name).name == name:
            allowed_names.add(name)
    return [
        {'name': path.name, 'target': path.stem, 'url': f'/api/v1/runs/{run_id}/screenshots/{path.name}'}
        for path in sorted(screenshot_dir.glob('*.png'))
        if path.name in allowed_names and path.is_file()
    ]


def activities_for_evidence(executions: list[dict[str, Any]]) -> list[str]:
    sources: list[str] = []
    actions: list[str] = []
    explicit: set[ActivityClass] = set()
    for execution in executions:
        source = str(execution.get('source') or execution.get('name') or '')
        activity = str(execution.get('activity') or '')
        if source.startswith('action:'):
            actions.append(source.removeprefix('action:'))
        else:
            sources.append(source)
        try:
            explicit.add(ActivityClass(activity))
        except ValueError:
            pass
    activities = set(activity_classes_for_selection(sources, actions)) | explicit
    if not activities:
        activities.add(ActivityClass.PASSIVE)
    return [activity.value for activity in ActivityClass if activity in activities]
