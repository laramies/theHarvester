import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Self
from uuid import UUID, uuid4

from theHarvester.lib.active_evidence import ActiveEvidence
from theHarvester.lib.asn_attribution import (
    AsnAttributionObservation,
    asn_attribution_details,
    canonical_asn_attributions,
    parse_asn_attribution_details,
)
from theHarvester.lib.evidence_types import (
    EVIDENCE_STATUSES,
    EXECUTION_STATUSES,
    RESULT_KINDS,
    EvidenceStatus,
    ExecutionStatus,
    ResultKind,
    format_utc,
)
from theHarvester.lib.network_evidence import (
    BgpRouteObservation,
    NetworkObservation,
    PrefixOriginObservation,
    RpkiValidationObservation,
    canonical_network_observations,
    network_observation_details,
    parse_network_observation_details,
)
from theHarvester.lib.result_values import normalize_result_value
from theHarvester.lib.shodan_evidence import ShodanHostObservation, canonical_shodan_hosts
from theHarvester.lib.virtual_host import VirtualHostObservation, normalize_virtual_host_hostname


def virtual_host_details(observations: Iterable[VirtualHostObservation]) -> list[dict[str, object]]:
    details: list[dict[str, object]] = []
    for observation in sorted(set(observations), key=VirtualHostObservation.sort_key):
        record = observation.to_record()
        details.append({key: value for key, value in record.items() if key not in {'type', 'hostname'}})
    return details


def parse_virtual_host_details(hostname: str, details: object) -> tuple[VirtualHostObservation, ...]:
    if not isinstance(details, list) or not details:
        raise ValueError('virtual-host details must be a non-empty array')
    observations: list[VirtualHostObservation] = []
    for detail in details:
        if not isinstance(detail, dict) or {'type', 'hostname'} & set(detail):
            raise ValueError('virtual-host details must contain endpoint evidence objects')
        observation = VirtualHostObservation.from_record({'type': 'vhost', 'hostname': hostname, **detail})
        if observation.hostname != hostname:
            raise ValueError('virtual-host result value must be a canonical hostname')
        if detail != virtual_host_details((observation,))[0]:
            raise ValueError('virtual-host details must use canonical structured evidence')
        observations.append(observation)
    return tuple(sorted(set(observations), key=VirtualHostObservation.sort_key))


def encode_result_jsonl(
    summary: Mapping[str, object],
    findings: Iterable[Mapping[str, object]],
) -> str:
    records = [{**summary, 'type': 'summary'}, *findings]
    return ''.join(json.dumps(record, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n' for record in records)


def parse_result_jsonl(payload: bytes | str) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        text = payload.decode('utf-8') if isinstance(payload, bytes) else payload
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('result file is not valid JSONL') from error
    if any(not isinstance(record, dict) for record in records):
        raise ValueError('JSONL records must be objects')
    summary = records[0] if records else None
    if not summary or summary.get('type') != 'summary':
        raise ValueError('JSONL must start with a summary record')
    if 'schema' in summary or 'schema_version' in summary:
        raise ValueError('JSONL must not contain a schema version')
    findings = records[1:]
    for record in findings:
        sources = record.get('sources', [])
        actions = record.get('actions', [])
        result_kind = record.get('type')
        allowed_keys = {'type', 'value', 'sources', 'actions'}
        if result_kind in {'asn', 'hostname', 'prefix'} and 'observations' in record:
            allowed_keys.add('observations')
        if result_kind == 'shodan-host' and 'details' in record:
            allowed_keys.add('details')
        if result_kind == 'prefix':
            allowed_keys.add('scope')
        if (
            set(record) - allowed_keys
            or result_kind not in RESULT_KINDS
            or not isinstance(record.get('value'), str)
            or not record['value'].strip()
            or not isinstance(sources, list)
            or any(not isinstance(source, str) or not source.strip() for source in sources)
            or not isinstance(actions, list)
            or any(not isinstance(action, str) or not action.strip() for action in actions)
        ):
            raise ValueError('JSONL findings must contain a known type, non-empty value, and producer names')
        result_value = record['value']
        try:
            normalized_result_value = normalize_result_value(result_kind, result_value)
            if result_kind == 'prefix' and normalized_result_value != result_value:
                raise ValueError('prefix result is not canonical')
        except ValueError as error:
            label = {'asn': 'ASN', 'prefix': 'prefix', 'shodan-host': 'Shodan host'}.get(str(result_kind), 'result')
            raise ValueError(f'JSONL findings must use a canonical {label} value') from error
        record['value'] = normalized_result_value
        if result_kind == 'prefix' and record.get('scope') != 'external-relationship':
            raise ValueError('JSONL prefix scope must be external-relationship')
        record['sources'] = sorted(set(sources))
        record['actions'] = sorted(set(actions))
        if result_kind == 'hostname' and 'observations' in record:
            try:
                observations = parse_virtual_host_details(record['value'], record.get('observations'))
            except ValueError as error:
                raise ValueError(f'JSONL hostname has invalid virtual-host observations: {error}') from error
            record['observations'] = virtual_host_details(observations)
        elif result_kind == 'prefix' and 'observations' in record:
            try:
                network_observations = parse_network_observation_details(result_value, record.get('observations'))
            except ValueError as error:
                raise ValueError(f'JSONL prefix has invalid network observations: {error}') from error
            record['observations'] = network_observation_details(network_observations)
        elif result_kind == 'asn' and 'observations' in record:
            try:
                asn_attributions = parse_asn_attribution_details(record['value'], record.get('observations'))
            except ValueError as error:
                raise ValueError(f'JSONL ASN has invalid organization attributions: {error}') from error
            record['observations'] = asn_attribution_details(asn_attributions)
        elif result_kind == 'shodan-host':
            try:
                shodan_host = ShodanHostObservation.from_record(record['value'], record.get('details'))
            except ValueError as error:
                raise ValueError(f'JSONL Shodan host has invalid details: {error}') from error
            if shodan_host.ip != record['value'] or shodan_host.to_details() != record.get('details'):
                raise ValueError('JSONL Shodan host must use canonical structured details')
            record['details'] = shodan_host.to_details()
    return summary, findings


@dataclass(frozen=True, order=True, slots=True)
class ResultObservation:
    source: str
    kind: ResultKind
    value: str

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError('observation source must not be empty')
        if self.kind not in RESULT_KINDS:
            raise ValueError(f'unknown observation kind: {self.kind}')
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError('observation value must be a non-empty string')
        object.__setattr__(self, 'value', normalize_result_value(self.kind, self.value))


@dataclass(frozen=True, slots=True)
class SourceExecution:
    """Record one source invocation without overstating the provider outcome.

    ``completed`` means the adapter returned normally. More precise statuses are
    used only when the adapter reports them or raises an exception. ``result_count``
    is the number of normalized, deduplicated observations attributed to the source.
    """

    source: str
    status: ExecutionStatus
    duration_ms: float
    result_count: int
    error_type: str | None = None
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError('source must not be empty')
        if self.status not in EXECUTION_STATUSES:
            raise ValueError(f'unknown execution status: {self.status}')
        if self.duration_ms < 0 or self.result_count < 0:
            raise ValueError('execution duration and result count must not be negative')

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'source': self.source,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, slots=True)
class SourceYield:
    source: str
    observed_result_count: int
    unique_result_count: int
    shared_result_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            'source': self.source,
            'observed_result_count': self.observed_result_count,
            'unique_result_count': self.unique_result_count,
            'shared_result_count': self.shared_result_count,
        }


@dataclass(frozen=True, slots=True)
class CompletedResult:
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    results: tuple[tuple[ResultKind, str], ...]
    source_executions: tuple[SourceExecution, ...] = ()
    observations: tuple[ResultObservation, ...] = ()
    active_evidence: ActiveEvidence = field(default_factory=ActiveEvidence)
    virtual_hosts: tuple[VirtualHostObservation, ...] = ()
    network_observations: tuple[NetworkObservation, ...] = ()
    asn_attributions: tuple[AsnAttributionObservation, ...] = ()
    shodan_hosts: tuple[ShodanHostObservation, ...] = ()
    evidence_status: EvidenceStatus | None = None

    def __post_init__(self) -> None:
        if not self.target.strip():
            raise ValueError('target must not be empty')
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError('started_at must be timezone-aware')
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError('completed_at must be timezone-aware')
        if self.completed_at < self.started_at:
            raise ValueError('completed_at must not be earlier than started_at')
        if not isinstance(self.run_id, UUID):
            raise ValueError('run_id must be a UUID')
        if any(kind not in RESULT_KINDS or not isinstance(value, str) or not value.strip() for kind, value in self.results):
            raise ValueError('results must contain known kinds and non-empty string values')
        if self.results != tuple(sorted(set(self.results))):
            raise ValueError('results must be deduplicated and sorted')
        if any(normalize_result_value(kind, value) != value for kind, value in self.results):
            raise ValueError('results must contain canonical values')
        if self.observations != tuple(sorted(set(self.observations))):
            raise ValueError('observations must be deduplicated and sorted')
        result_set = set(self.results)
        if any((observation.kind, observation.value) not in result_set for observation in self.observations):
            raise ValueError('every observation must reference a completed result')
        execution_sources = [execution.source for execution in self.source_executions]
        execution_source_set = set(execution_sources)
        if len(execution_sources) != len(execution_source_set):
            raise ValueError('source executions must be unique')
        if any(observation.source not in execution_source_set for observation in self.observations):
            raise ValueError('every observation must reference a matching source execution')
        observation_counts = Counter(observation.source for observation in self.observations)
        if any(execution.result_count != observation_counts[execution.source] for execution in self.source_executions):
            raise ValueError('source execution result count must match its attributed observations')
        if any(
            (observation.kind, observation.value) not in result_set for _action, observation in self.active_evidence.observations
        ):
            raise ValueError('every action observation must reference a completed result')
        if any(
            (artifact.subject_kind, artifact.subject_value) not in result_set
            for _action, artifact in self.active_evidence.artifacts
        ):
            raise ValueError('every artifact must reference a completed result')
        sorted_virtual_hosts = tuple(sorted(set(self.virtual_hosts), key=VirtualHostObservation.sort_key))
        if self.virtual_hosts != sorted_virtual_hosts:
            raise ValueError('virtual-host observations must be deduplicated and sorted')
        if self.virtual_hosts:
            try:
                virtual_host_scope = normalize_virtual_host_hostname(self.target)
            except ValueError as error:
                raise ValueError('virtual-host observations require a hostname run target scope') from error
        for observation in self.virtual_hosts:
            if observation.hostname == virtual_host_scope or not observation.hostname.endswith(f'.{virtual_host_scope}'):
                raise ValueError('virtual-host observation must be a descendant of the run target scope')
            try:
                canonical = parse_virtual_host_details(
                    observation.hostname,
                    virtual_host_details((observation,)),
                )
            except ValueError as error:
                raise ValueError('virtual-host observations must contain canonical distinct evidence') from error
            if canonical != (observation,):
                raise ValueError('virtual-host observations must contain canonical distinct evidence')
        structured_vhost_results = {('hostname', observation.hostname) for observation in self.virtual_hosts}
        if not structured_vhost_results.issubset(result_set):
            raise ValueError('every virtual-host observation must reference a hostname result')
        vhost_action_results = {
            (observation.kind, observation.value)
            for action, observation in self.active_evidence.observations
            if action == 'vhost'
        }
        if vhost_action_results != structured_vhost_results:
            raise ValueError('structured virtual-host evidence must exactly match vhost action provenance')
        sorted_network_observations = canonical_network_observations(self.network_observations)
        if self.network_observations != sorted_network_observations:
            raise ValueError('network observations must be deduplicated and sorted')
        if any(
            observation.collected_at < self.started_at or observation.collected_at > self.completed_at
            for observation in self.network_observations
        ):
            raise ValueError('network observation collection time must fall within the completed run')
        action_results = {
            (action, observation.kind, observation.value) for action, observation in self.active_evidence.observations
        }
        origin_observations = {
            (observation.action, observation.prefix, observation.origin_asn)
            for observation in self.network_observations
            if isinstance(observation, PrefixOriginObservation)
        }
        for network_observation in self.network_observations:
            if ('prefix', network_observation.prefix) not in result_set or (
                'asn',
                network_observation.origin_asn,
            ) not in result_set:
                raise ValueError('network observation must reference completed prefix and ASN results')
            if (network_observation.action, 'prefix', network_observation.prefix) not in action_results:
                raise ValueError('network observation must reference matching action prefix provenance')
            if (
                isinstance(network_observation, BgpRouteObservation | RpkiValidationObservation)
                and (
                    network_observation.action,
                    network_observation.prefix,
                    network_observation.origin_asn,
                )
                not in origin_observations
            ):
                raise ValueError('BGP route and RPKI observations require matching observed-origin evidence')
        sorted_shodan_hosts = canonical_shodan_hosts(list(self.shodan_hosts))
        if self.shodan_hosts != sorted_shodan_hosts:
            raise ValueError('Shodan host observations must be deduplicated and sorted')
        structured_shodan_results = {('shodan-host', observation.ip) for observation in self.shodan_hosts}
        if structured_shodan_results != {result for result in result_set if result[0] == 'shodan-host'}:
            raise ValueError('Shodan host results must contain canonical structured evidence')
        source_results = {(observation.source, observation.kind, observation.value) for observation in self.observations}
        action_results = {
            (action, observation.kind, observation.value) for action, observation in self.active_evidence.observations
        }
        for shodan_observation in self.shodan_hosts:
            if ('shodan', 'shodan-host', shodan_observation.ip) not in source_results and (
                'shodan',
                'shodan-host',
                shodan_observation.ip,
            ) not in action_results:
                raise ValueError('Shodan host evidence must reference Shodan source or action provenance')
        sorted_asn_attributions = canonical_asn_attributions(list(self.asn_attributions))
        if self.asn_attributions != sorted_asn_attributions:
            raise ValueError('ASN attributions must be deduplicated and sorted')
        for attribution in self.asn_attributions:
            if attribution.collected_at < self.started_at or attribution.collected_at > self.completed_at:
                raise ValueError('ASN attribution collection time must fall within the completed run')
            if ('asn', attribution.asn) not in result_set or (
                attribution.subject_kind,
                attribution.subject_value,
            ) not in result_set:
                raise ValueError('ASN attribution must reference completed ASN and subject results')
            producer_result_set = source_results if attribution.producer_kind == 'source' else action_results
            if (
                attribution.producer,
                'asn',
                attribution.asn,
            ) not in producer_result_set or (
                attribution.producer,
                attribution.subject_kind,
                attribution.subject_value,
            ) not in producer_result_set:
                raise ValueError('ASN attribution must reference matching producer provenance')
        if self.evidence_status is not None and self.evidence_status not in EVIDENCE_STATUSES:
            raise ValueError('evidence status must be complete, partial, or failed')

    @classmethod
    def finish(
        cls,
        *,
        run_id: UUID | None = None,
        target: str,
        started_at: datetime,
        completed_at: datetime,
        groups: Mapping[ResultKind, Iterable[str]],
        source_executions: Iterable[SourceExecution] = (),
        observations: Iterable[ResultObservation] = (),
        active_evidence: ActiveEvidence | None = None,
        virtual_hosts: Iterable[VirtualHostObservation] = (),
        network_observations: Iterable[NetworkObservation] = (),
        asn_attributions: Iterable[AsnAttributionObservation] = (),
        shodan_hosts: Iterable[ShodanHostObservation] = (),
        evidence_status: EvidenceStatus | None = None,
    ) -> Self:
        completed_active_evidence = active_evidence if active_evidence is not None else ActiveEvidence()
        results: set[tuple[ResultKind, str]] = set()
        for kind, values in groups.items():
            if kind not in RESULT_KINDS:
                raise ValueError(f'unknown result kind: {kind}')
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError('results must contain non-empty string values')
                normalized_value = normalize_result_value(kind, value)
                results.add((kind, normalized_value))
        for _action, action_observation in completed_active_evidence.observations:
            results.add((action_observation.kind, action_observation.value))
        completed_virtual_hosts = tuple(sorted(set(virtual_hosts), key=VirtualHostObservation.sort_key))
        for virtual_host in completed_virtual_hosts:
            results.add(('hostname', virtual_host.hostname))
        completed_shodan_hosts = canonical_shodan_hosts(list(shodan_hosts))
        for shodan_host in completed_shodan_hosts:
            results.add(('shodan-host', shodan_host.ip))
        return cls(
            run_id=run_id or uuid4(),
            target=target.strip(),
            started_at=started_at,
            completed_at=completed_at,
            results=tuple(sorted(results)),
            source_executions=tuple(source_executions),
            observations=tuple(sorted(set(observations))),
            active_evidence=completed_active_evidence,
            virtual_hosts=completed_virtual_hosts,
            network_observations=canonical_network_observations(network_observations),
            asn_attributions=canonical_asn_attributions(list(asn_attributions)),
            shodan_hosts=completed_shodan_hosts,
            evidence_status=evidence_status,
        )

    def evidence_dict(self) -> dict[str, object]:
        return {
            'run_id': str(self.run_id),
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'status': self.status,
            'results': self._result_records(include_actions=True),
            'source_executions': [execution.to_dict() for execution in self.source_executions],
            'action_executions': [execution.to_dict() for execution in self.active_evidence.executions],
            'artifacts': [{'action': action, **artifact.to_dict()} for action, artifact in self.active_evidence.artifacts],
        }

    def jsonl(self) -> str:
        counts = Counter(kind for kind, _value in self.results)
        return encode_result_jsonl(
            {
                'completed_at': format_utc(self.completed_at),
                'counts': dict(sorted(counts.items())),
                'evidence_status': self.status,
                'result_count': len(self.results),
                'run_id': str(self.run_id),
                'source_executions': [execution.to_dict() for execution in self.source_executions],
                'action_executions': [execution.to_dict() for execution in self.active_evidence.executions],
                'artifacts': [{'action': action, **artifact.to_dict()} for action, artifact in self.active_evidence.artifacts],
                'started_at': format_utc(self.started_at),
                'target': self.target,
            },
            self._result_records(include_actions=True),
        )

    @property
    def status(self) -> str:
        incomplete = {'partial', 'failed', 'rate-limited', 'skipped'}
        execution_statuses = [execution.status for execution in self.source_executions]
        execution_statuses.extend(execution.status for execution in self.active_evidence.executions)
        if execution_statuses and all(status == 'failed' for status in execution_statuses):
            return 'failed'
        if any(execution_status in incomplete for execution_status in execution_statuses):
            return 'partial'
        if execution_statuses:
            return 'complete'
        return self.evidence_status or 'complete'

    def _result_records(self, *, include_actions: bool) -> list[dict[str, object]]:
        sources_by_result: dict[tuple[ResultKind, str], list[str]] = {}
        for source_observation in self.observations:
            sources_by_result.setdefault((source_observation.kind, source_observation.value), []).append(
                source_observation.source
            )
        actions_by_result: dict[tuple[ResultKind, str], list[str]] = {}
        for action, action_observation in self.active_evidence.observations:
            actions_by_result.setdefault((action_observation.kind, action_observation.value), []).append(action)
        vhosts_by_hostname: dict[str, list[VirtualHostObservation]] = {}
        for virtual_host in self.virtual_hosts:
            vhosts_by_hostname.setdefault(virtual_host.hostname, []).append(virtual_host)
        network_by_prefix: dict[str, list[NetworkObservation]] = {}
        for observation in self.network_observations:
            network_by_prefix.setdefault(observation.prefix, []).append(observation)
        attribution_by_asn: dict[str, list[AsnAttributionObservation]] = {}
        for attribution in self.asn_attributions:
            attribution_by_asn.setdefault(attribution.asn, []).append(attribution)
        shodan_by_ip = {observation.ip: observation for observation in self.shodan_hosts}
        records: list[dict[str, object]] = []
        for kind, value in self.results:
            record: dict[str, object] = {
                'type': kind,
                'value': value,
                'sources': sources_by_result.get((kind, value), []),
            }
            if include_actions and (actions := actions_by_result.get((kind, value))):
                record['actions'] = actions
            if kind == 'prefix':
                record['scope'] = 'external-relationship'
            if kind == 'hostname' and (virtual_hosts := vhosts_by_hostname.get(value)):
                record['observations'] = virtual_host_details(virtual_hosts)
            elif kind == 'prefix' and (network_observations := network_by_prefix.get(value)):
                record['observations'] = network_observation_details(tuple(network_observations))
            elif kind == 'asn' and (asn_attributions := attribution_by_asn.get(value)):
                record['observations'] = asn_attribution_details(tuple(asn_attributions))
            elif kind == 'shodan-host' and (shodan_host := shodan_by_ip.get(value)):
                record['details'] = shodan_host.to_details()
            records.append(record)
        return records
