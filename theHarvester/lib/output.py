from __future__ import annotations

import json
import logging
import sys
from collections.abc import Hashable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, TypeVar, cast
from xml.etree.ElementTree import Element, SubElement, tostring

from theHarvester.lib.dns_validation import Addressability
from theHarvester.lib.run import ActivityClass, ScopeClass, StageFindingKind, legacy_hostnames

if TYPE_CHECKING:
    from collections.abc import Mapping

    from theHarvester.lib.run import MergedEntity, RunResult, SelectedObservation

T = TypeVar('T', bound=Hashable)


class _OperatorOutputHandler(logging.Handler):
    """Write operator-facing messages to the current stdout stream."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(f'{self.format(record)}\n')
        except Exception:
            self.handleError(record)


output_logger = logging.getLogger('theHarvester.output')


def configure_logging(*, verbose: bool) -> None:
    """Configure CLI diagnostics without taking ownership from an embedding host."""
    if not any(isinstance(handler, _OperatorOutputHandler) for handler in output_logger.handlers):
        output_logger.addHandler(_OperatorOutputHandler())
    output_logger.setLevel(logging.INFO)
    output_logger.propagate = False

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s: %(message)s'))
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.WARNING)

    package_logger = logging.getLogger('theHarvester')
    logger_state = package_logger.__dict__
    if verbose and package_logger.level != logging.INFO:
        logger_state.setdefault('_theharvester_level_before_verbose', package_logger.level)
        package_logger.setLevel(logging.INFO)
    elif not verbose and '_theharvester_level_before_verbose' in logger_state:
        previous_level = logger_state.pop('_theharvester_level_before_verbose')
        if package_logger.level == logging.INFO:
            package_logger.setLevel(previous_level)


def sorted_unique[T: Hashable](items: Iterable[T]) -> list[T]:
    unique_items = list(dict.fromkeys(items))
    unique_items.sort(key=lambda item: str(item))
    return unique_items


def print_section(header: str, items: Iterable[str], separator: str) -> None:
    output_logger.info(header)
    output_logger.info(separator)
    for item in sorted_unique(items):
        output_logger.info(item)


def print_linkedin_sections(
    engines: Sequence[str], people: Sequence[str], links: Sequence[str], separator: str = '---------------------'
) -> None:
    if len(people) == 0 and 'linkedin' in engines:
        output_logger.info('\n[*] No LinkedIn users found.\n\n')
    elif len(people) >= 1:
        output_logger.info(f'\n[*] LinkedIn Users found: {len(people)}')
        output_logger.info(separator)
        for usr in sorted_unique(people):
            output_logger.info(usr)

    if 'linkedin' in engines or 'rocketreach' in engines:
        output_logger.info(f'\n[*] LinkedIn Links found: {len(links)}')
        output_logger.info(separator)
        for link in sorted_unique(links):
            output_logger.info(link)


def _entity_line(entity: MergedEntity, selected: Sequence[SelectedObservation] = ()) -> str:
    sources = ','.join(sorted({observation.source for observation in entity.observations}))
    selected_status = ''.join(f'; {observation.kind}={observation.detail or "observed"}' for observation in selected)
    status = (
        entity.addressability
        or ('scope-extension-candidate' if ScopeClass.SCOPE_EXTENSION in entity.scope_classes else None)
        or ('external-relationship' if ScopeClass.EXTERNAL_RELATIONSHIP in entity.scope_classes else None)
        or 'needs-review'
    )
    return f'{entity.value} [status={status}; sources={sources}{selected_status}]'


def format_run_terminal(result: RunResult) -> str:
    """Render one concise terminal report from a completed evidence run."""
    primary = [
        entity
        for entity in result.entities
        if ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is Addressability.CURRENT
    ]
    primary_values = {entity.value for entity in primary}
    secondary = [
        entity
        for entity in result.entities
        if entity.value not in primary_values
        and (
            ScopeClass.EXTERNAL_RELATIONSHIP in entity.scope_classes
            or (ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is not Addressability.CURRENT)
        )
    ]
    reported_values = primary_values | {entity.value for entity in secondary}
    scope_extensions = [
        entity
        for entity in result.entities
        if entity.value not in reported_values and ScopeClass.SCOPE_EXTENSION in entity.scope_classes
    ]
    entity_values = {entity.value for entity in result.entities}
    selected_by_entity = {
        value: tuple(observation for observation in result.selected_observations if observation.value == value)
        for value in entity_values
    }
    standalone_selected = [observation for observation in result.selected_observations if observation.value not in entity_values]
    passive_stages = [stage.stage for stage in result.stage_executions if stage.activity_class is ActivityClass.PASSIVE]
    dns_activities = [
        *(['dns-consensus'] if result.dns_validations else []),
        *(stage.stage for stage in result.stage_executions if stage.activity_class is ActivityClass.DNS),
    ]
    direct_activities = [stage.stage for stage in result.stage_executions if stage.activity_class is ActivityClass.DIRECT]
    source_count = len(result.source_executions)
    passive_summary = f'{source_count} source{"s" if source_count != 1 else ""}'
    if passive_stages:
        passive_summary = f'{passive_summary}, {", ".join(passive_stages)}'
    activity_summary = (
        f'[*] Activity summary: {ActivityClass.PASSIVE}={passive_summary}; '
        f'{ActivityClass.DNS}={", ".join(dns_activities) or "none"}; '
        f'{ActivityClass.DIRECT}={", ".join(direct_activities) or "none"}'
    )
    selected_sections: list[str] = []
    for kind, title in (
        (StageFindingKind.EMAIL, 'Emails found'),
        (StageFindingKind.IP_ADDRESS, 'IPs found'),
        (StageFindingKind.ASN, 'ASNS found'),
        (StageFindingKind.PERSON, 'People found'),
        (StageFindingKind.URL, 'URLs found'),
        (StageFindingKind.INTERESTING_URL, 'Interesting Urls found'),
        (StageFindingKind.TAKEOVER, 'Takeover results'),
        (StageFindingKind.SCREENSHOT, 'Screenshots captured'),
        (StageFindingKind.SHODAN_RESULT, 'Shodan results'),
        (StageFindingKind.API_ENDPOINT, 'API Endpoints found'),
        (StageFindingKind.API_AUTH_REQUIRED, 'Endpoints requiring authentication'),
        (StageFindingKind.API_VERSION, 'Detected API versions'),
        (StageFindingKind.API_RATE_LIMIT, 'Rate limited endpoints'),
        (StageFindingKind.HTTP_METHOD, 'HTTP methods used'),
        (StageFindingKind.HTTP_STATUS_CODE, 'HTTP status codes encountered'),
    ):
        observations = [observation for observation in standalone_selected if observation.kind is kind]
        if not observations:
            continue
        by_value: dict[str, list[SelectedObservation]] = {}
        for observation in observations:
            by_value.setdefault(observation.value, []).append(observation)
        selected_sections.append(f'[*] {title}: {len(by_value)}')
        for value, value_observations in sorted(by_value.items()):
            sources = ','.join(sorted({observation.source for observation in value_observations}))
            details = ', '.join(sorted({observation.detail for observation in value_observations if observation.detail}))
            detail = f'; detail={details}' if details else ''
            selected_sections.append(f'{value} [status=observed; sources={sources}{detail}]')
    sections = [
        f'[*] Run status: {result.status}',
        activity_summary,
        f'[*] Currently addressable subdomains ({len(primary)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in primary),
        f'[*] Secondary evidence / needs review ({len(secondary)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in secondary),
        f'[*] Scope-extension candidates ({len(scope_extensions)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in scope_extensions),
        *selected_sections,
        '[*] Source executions',
        *(
            f'{execution.source} [status={execution.status}; results={execution.result_count}; '
            f'observations={execution.observation_count}]'
            for execution in result.source_executions
        ),
        '[*] Selected stage executions',
        *(
            f'{execution.stage} [status={execution.status}; results={execution.result_count}; '
            f'observations={execution.observation_count}]'
            for execution in result.stage_executions
        ),
    ]
    return '\n'.join(sections)


def run_result_jsonl(result: RunResult) -> str:
    """Serialize a completed run as versioned, normalized evidence records."""
    serialized = result.to_dict()
    records: list[tuple[str, dict[str, Any]]] = [('run', _run_record(result))]
    records.extend(('source_execution', item) for item in cast('list[dict[str, Any]]', serialized['source_executions']))
    records.extend(('stage_execution', item) for item in cast('list[dict[str, Any]]', serialized['stage_executions']))
    records.extend(('discovery_observation', item) for item in cast('list[dict[str, Any]]', serialized['observations']))
    for item in cast('list[dict[str, Any]]', serialized['dns_validations']):
        validation = dict(item)
        validation['validated_at'] = validation.pop('queried_at')
        records.append(('dns_validation_observation', validation))
    for item in cast('list[dict[str, Any]]', serialized['entities']):
        merged = dict(item)
        merged['provenance'] = merged.pop('observations')
        records.append(('merged_result', merged))
    records.extend(('selected_observation', item) for item in cast('list[dict[str, Any]]', serialized['selected_observations']))
    return '\n'.join(
        json.dumps(
            {
                'schema_version': 'theharvester-evidence-v1',
                'run_id': result.run_id,
                'target': result.target,
                'record_type': record_type,
                'data': data,
            }
        )
        for record_type, data in records
    )


def _run_record(result: RunResult) -> dict[str, object]:
    return {
        'run_id': result.run_id,
        'target': result.target,
        'status': result.status,
        'started_at': result.started_at.isoformat(),
        'completed_at': result.completed_at.isoformat(),
        'record_counts': {
            'source_executions': len(result.source_executions),
            'stage_executions': len(result.stage_executions),
            'discovery_observations': len(result.observations),
            'dns_validation_observations': len(result.dns_validations),
            'merged_results': len(result.entities),
            'selected_observations': len(result.selected_observations),
        },
    }


def legacy_json_result(result: RunResult, existing: Mapping[str, object] | None = None) -> dict[str, object]:
    adapted = dict(existing or {})
    existing_hosts = adapted.get('hosts', [])
    hosts = list(existing_hosts) if isinstance(existing_hosts, list) else []
    represented_hosts = {host.split(':', 1)[0] for host in hosts if isinstance(host, str)}
    hosts.extend(host for host in legacy_hostnames(result) if host not in represented_hosts)
    adapted['hosts'] = list(dict.fromkeys(hosts))
    adapted['evidence_run'] = {
        **_run_record(result),
        'source_executions': [execution.to_dict() for execution in result.source_executions],
        'stage_executions': [execution.to_dict() for execution in result.stage_executions],
        'merged_results': [entity.to_dict() for entity in result.entities],
        'selected_observations': [observation.to_dict() for observation in result.selected_observations],
    }
    return adapted


def evidence_xml_fragment(result: RunResult) -> str:
    evidence_run = Element('evidence_run', run_id=result.run_id, status=result.status)
    for execution in result.source_executions:
        SubElement(
            evidence_run,
            'source',
            name=execution.source,
            status=execution.status,
            activity_class=execution.activity_class,
        )
    for stage_execution in result.stage_executions:
        SubElement(
            evidence_run,
            'stage',
            name=stage_execution.stage,
            status=stage_execution.status,
            activity_class=stage_execution.activity_class,
        )
    for entity in result.entities:
        attributes = {
            'value': entity.value,
            'scope_classes': ','.join(sorted(entity.scope_classes)),
            'sources': ','.join(sorted({observation.source for observation in entity.observations})),
        }
        if entity.addressability is not None:
            attributes['addressability'] = entity.addressability
        SubElement(evidence_run, 'merged_result', attributes)
    for observation in result.selected_observations:
        attributes = {
            'source': observation.source,
            'kind': observation.kind,
            'value': observation.value,
            'collected_at': observation.collected_at.isoformat(),
        }
        if observation.detail is not None:
            attributes['detail'] = observation.detail
        SubElement(evidence_run, 'selected_observation', attributes)
    return tostring(evidence_run, encoding='unicode')
