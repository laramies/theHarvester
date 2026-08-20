from __future__ import annotations

from pathlib import Path
from typing import Any

from theHarvester.lib.source_catalog import (
    ActivityClass,
    SourceSpec,
    activity_classes_for_selection,
    get_source_spec,
    selected_action_names,
)


def activities_for_request(request: dict[str, Any]) -> list[str]:
    if request.get('activities'):
        return list(request['activities'])
    actions = selected_action_names(request)
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
    for item in evidence.get('results') or []:
        if isinstance(item, dict) and item.get('type') != 'screenshot':
            result: dict[str, Any] = {
                'type': str(item.get('type', 'other')),
                'value': str(item.get('value', '')),
                'sources': sorted({str(source) for source in item.get('sources', [])}),
                'actions': sorted({str(action) for action in item.get('actions', [])}),
            }
            if item.get('type') in {'asn', 'hostname', 'prefix'} and item.get('observations'):
                result['observations'] = [
                    dict(observation) for observation in item.get('observations', []) if isinstance(observation, dict)
                ]
            if item.get('type') in {'shodan-host', 'takeover'} and isinstance(item.get('details'), dict):
                result['details'] = dict(item['details'])
            if item.get('type') == 'prefix':
                result['scope'] = str(item.get('scope', ''))
            results.append(result)
    return results


def source_executions(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    executions = evidence.get('source_executions') or []
    return [dict(execution) for execution in executions if isinstance(execution, dict)]


def screenshots(evidence: dict[str, Any] | None, run_id: str, artifact_dir: Path) -> list[dict[str, Any]]:
    screenshot_dir = artifact_dir / 'screenshots'
    if not screenshot_dir.is_dir():
        return []
    allowed_names: set[str] = set()
    targets: dict[str, str] = {}
    for artifact in (evidence or {}).get('artifacts') or []:
        if not isinstance(artifact, dict) or artifact.get('kind') != 'screenshot':
            continue
        file = artifact.get('file')
        subject = artifact.get('subject')
        if not isinstance(file, dict) or not isinstance(subject, dict):
            continue
        name = Path(str(file.get('path', ''))).name
        if name and name.endswith('.png'):
            allowed_names.add(name)
            targets[name] = str(subject.get('value') or Path(name).stem)
    return [
        {
            'name': path.name,
            'target': targets.get(path.name, path.stem),
            'url': f'/api/v1/runs/{run_id}/screenshots/{path.name}',
        }
        for path in sorted(screenshot_dir.glob('*.png'))
        if path.name in allowed_names and path.is_file()
    ]


def activities_for_evidence(
    source_executions: list[dict[str, Any]],
    action_executions: list[dict[str, Any]],
) -> list[str]:
    sources = [str(execution.get('source', '')) for execution in source_executions]
    actions = [str(execution.get('action', '')) for execution in action_executions]
    explicit: set[ActivityClass] = set()
    for execution in (*source_executions, *action_executions):
        activity = str(execution.get('activity') or '')
        try:
            explicit.add(ActivityClass(activity))
        except ValueError:
            pass
    activities = set(activity_classes_for_selection(sources, actions)) | explicit
    if not activities:
        activities.add(ActivityClass.PASSIVE)
    return [activity.value for activity in ActivityClass if activity in activities]
