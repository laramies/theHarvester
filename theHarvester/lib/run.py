from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

import aiosqlite

from theHarvester.lib.dns_validation import (
    Addressability,
    DnsValidationObservation,
    DnsValidator,
)
from theHarvester.lib.hostnames import normalize_hostname

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence

logger = logging.getLogger(__name__)


class Derivation(StrEnum):
    PROVIDER = 'provider'
    SCOPE_EXTENSION = 'scope-extension'
    EXTERNAL_RELATIONSHIP = 'external-relationship'


class ScopeClass(StrEnum):
    IN_SCOPE = 'in-scope'
    SCOPE_EXTENSION = 'scope-extension'
    EXTERNAL_RELATIONSHIP = 'external-relationship'


class SourceStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    PARTIAL = 'partial'
    EMPTY = 'empty'
    FAILED = 'failed'
    RATE_LIMITED = 'rate-limited'


class RunStatus(StrEnum):
    COMPLETE = 'complete'
    PARTIAL = 'partial'
    FAILED = 'failed'


class ActivityClass(StrEnum):
    PASSIVE = 'P0 passive collection'
    DNS = 'P1 DNS interaction'
    DIRECT = 'P2 direct interaction'


@dataclass(frozen=True)
class SourceFinding:
    value: str
    derivation: Derivation = Derivation.PROVIDER
    observed_at: datetime | None = None


class StageFindingKind(StrEnum):
    HOSTNAME = 'hostname'
    EMAIL = 'email'
    IP_ADDRESS = 'ip-address'
    PERSON = 'person'
    URL = 'url'
    INTERESTING_URL = 'interesting-url'
    ASN = 'asn'
    TAKEOVER = 'takeover'
    API_ENDPOINT = 'api-endpoint'
    SCREENSHOT = 'screenshot'
    SHODAN_RESULT = 'shodan-result'
    API_AUTH_REQUIRED = 'api-auth-required'
    API_VERSION = 'api-version'
    API_RATE_LIMIT = 'api-rate-limit'
    HTTP_METHOD = 'http-method'
    HTTP_STATUS_CODE = 'http-status-code'


@dataclass(frozen=True)
class StageFinding:
    kind: StageFindingKind
    value: str
    detail: str | None = None
    derivation: Derivation = Derivation.PROVIDER


@dataclass(frozen=True)
class StageResult:
    source: str
    status: SourceStatus
    duration_ms: float
    result_count: int
    findings: tuple[StageFinding, ...] = ()
    source_family: str | None = None
    error_type: str | None = None
    is_action: bool = False
    activity_class: ActivityClass | None = None
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.is_action and self.activity_class is None:
            raise ValueError('action stages require an explicit activity class')


class SourceIncompleteError(Exception):
    status = SourceStatus.FAILED

    def __init__(self, message: str = '', *, findings: Sequence[SourceFinding] = ()) -> None:
        super().__init__(message)
        self.findings = tuple(findings)


class SourceRateLimitedError(SourceIncompleteError):
    status = SourceStatus.RATE_LIMITED


class SourcePartialError(SourceIncompleteError):
    status = SourceStatus.PARTIAL


class PassiveSource(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def family(self) -> str: ...

    async def collect(self, target: str) -> Sequence[SourceFinding]: ...


class LegacyHostnameSearch(Protocol):
    async def process(self, proxy: bool = False) -> None: ...

    async def get_hostnames(self) -> Collection[str]: ...


@dataclass(frozen=True)
class LegacyHostnameSource:
    name: str
    legacy_name: str
    family: str
    search: LegacyHostnameSearch
    proxy: bool = False

    async def collect(self, _target: str) -> tuple[SourceFinding, ...]:
        await self.search.process(self.proxy)
        return tuple(SourceFinding(hostname) for hostname in await self.search.get_hostnames())


@dataclass(frozen=True)
class DiscoveryObservation:
    """One normalized source assertion retained before entity merging."""

    run_id: str
    target: str
    value: str
    source: str
    source_family: str
    derivation: Derivation
    collected_at: datetime
    scope_class: ScopeClass
    provider_observed_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            'run_id': self.run_id,
            'target': self.target,
            'value': self.value,
            'source': self.source,
            'source_family': self.source_family,
            'derivation': self.derivation,
            'collected_at': self.collected_at.isoformat(),
            'scope_class': self.scope_class,
        }
        if self.provider_observed_at is not None:
            result['provider_observed_at'] = self.provider_observed_at.isoformat()
        return result


@dataclass(frozen=True)
class SourceExecution:
    """Completion status and counts for one source attempt in a run."""

    run_id: str
    source: str
    source_family: str
    status: SourceStatus
    duration_ms: float
    result_count: int
    observation_count: int
    entity_count: int
    activity_class: ActivityClass = ActivityClass.PASSIVE
    error_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'source': self.source,
            'source_family': self.source_family,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'observation_count': self.observation_count,
            'entity_count': self.entity_count,
            'activity_class': self.activity_class,
            'error_type': self.error_type,
        }


@dataclass(frozen=True)
class StageExecution:
    run_id: str
    stage: str
    status: SourceStatus
    duration_ms: float
    result_count: int
    observation_count: int
    entity_count: int
    completed_at: datetime
    activity_class: ActivityClass
    error_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'stage': self.stage,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'observation_count': self.observation_count,
            'entity_count': self.entity_count,
            'completed_at': self.completed_at.isoformat(),
            'activity_class': self.activity_class,
            'error_type': self.error_type,
        }


@dataclass(frozen=True)
class SelectedObservation:
    run_id: str
    source: str
    kind: StageFindingKind
    value: str
    detail: str | None
    derivation: Derivation
    collected_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'source': self.source,
            'kind': self.kind,
            'value': self.value,
            'detail': self.detail,
            'derivation': self.derivation,
            'collected_at': self.collected_at.isoformat(),
        }


@dataclass(frozen=True)
class MergedEntity:
    value: str
    observations: tuple[DiscoveryObservation, ...]
    addressability: Addressability | None = None

    @property
    def scope_classes(self) -> tuple[ScopeClass, ...]:
        return tuple(dict.fromkeys(observation.scope_class for observation in self.observations))

    @property
    def independent_corroboration_count(self) -> int:
        """Count independent datasets, not the number of reporting adapters.

        Two adapters backed by one provider can corroborate transport or parser
        behavior, but they cannot independently corroborate the discovered name.
        """

        return len({observation.source_family for observation in self.observations})

    def to_dict(self) -> dict[str, object]:
        return {
            'value': self.value,
            'addressability': self.addressability,
            'scope_classes': list(self.scope_classes),
            'independent_corroboration_count': self.independent_corroboration_count,
            'observations': [observation.to_dict() for observation in self.observations],
        }


@dataclass(frozen=True)
class RunResult:
    run_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    source_executions: tuple[SourceExecution, ...]
    observations: tuple[DiscoveryObservation, ...]
    entities: tuple[MergedEntity, ...]
    dns_validations: tuple[DnsValidationObservation, ...] = ()
    selected_observations: tuple[SelectedObservation, ...] = ()
    stage_executions: tuple[StageExecution, ...] = ()

    @property
    def status(self) -> RunStatus:
        statuses = [
            *(execution.status for execution in self.source_executions),
            *(execution.status for execution in self.stage_executions),
        ]
        incomplete = {SourceStatus.PARTIAL, SourceStatus.FAILED, SourceStatus.RATE_LIMITED}
        if statuses and all(status is SourceStatus.FAILED for status in statuses):
            return RunStatus.FAILED
        if any(status in incomplete for status in statuses):
            return RunStatus.PARTIAL
        return RunStatus.COMPLETE

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'status': self.status,
            'source_executions': [execution.to_dict() for execution in self.source_executions],
            'stage_executions': [execution.to_dict() for execution in self.stage_executions],
            'observations': [observation.to_dict() for observation in self.observations],
            'dns_validations': [
                {
                    'run_id': observation.run_id,
                    'candidate': observation.candidate,
                    'query_name': observation.query_name,
                    'resolver': observation.resolver,
                    'queried_at': observation.queried_at.isoformat(),
                    'ipv4': list(observation.ipv4),
                    'ipv6': list(observation.ipv6),
                    'cnames': list(observation.cnames),
                    'rcode': observation.rcode,
                    'ttl': observation.ttl,
                    'cname_chain': list(observation.cname_chain),
                    'latency_ms': observation.latency_ms,
                    'error': observation.error,
                    'is_wildcard_control': observation.is_wildcard_control,
                    'wildcard_depth': observation.wildcard_depth,
                    'activity_class': ActivityClass.DNS,
                }
                for observation in self.dns_validations
            ],
            'entities': [entity.to_dict() for entity in self.entities],
            'selected_observations': [observation.to_dict() for observation in self.selected_observations],
        }


class SQLiteRunStore:
    def __init__(self, database: str | Path | None = None) -> None:
        self.database = Path(database) if database is not None else Path('~/.local/share/theHarvester/stash.sqlite').expanduser()

    async def save(self, result: RunResult) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                )
                """
            )
            await database.execute(
                'INSERT INTO evidence_runs (run_id, target, completed_at, evidence_json) VALUES (?, ?, ?, ?)',
                (
                    result.run_id,
                    result.target,
                    result.completed_at.isoformat(),
                    json.dumps(result.to_dict()),
                ),
            )
            await database.commit()

    async def load(self, run_id: str) -> dict[str, object] | None:
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute(
                'SELECT evidence_json FROM evidence_runs WHERE run_id = ?',
                (run_id,),
            )
            row = await cursor.fetchone()
        return json.loads(row[0]) if row is not None else None


def _classify_scope(target: str, value: str, derivation: Derivation) -> ScopeClass:
    if value == target or value.endswith(f'.{target}'):
        return ScopeClass.IN_SCOPE
    if derivation is Derivation.EXTERNAL_RELATIONSHIP:
        return ScopeClass.EXTERNAL_RELATIONSHIP
    return ScopeClass.SCOPE_EXTENSION


def _merge_observations(observations: Sequence[DiscoveryObservation]) -> tuple[MergedEntity, ...]:
    grouped: dict[str, list[DiscoveryObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.value, []).append(observation)
    return tuple(MergedEntity(value, tuple(supporting)) for value, supporting in grouped.items())


async def validate_run(
    result: RunResult,
    dns_validator: DnsValidator,
    *,
    deterministic_exact_dns_names: tuple[str, ...] = (),
) -> RunResult:
    candidates = tuple(
        entity.value
        for entity in result.entities
        if ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is None
    )
    if not candidates:
        return result
    validation = await dns_validator.validate(
        result.run_id,
        result.target,
        candidates,
        deterministic_exact_names=deterministic_exact_dns_names,
    )
    classifications = {classification.candidate: classification.addressability for classification in validation.classifications}
    return replace(
        result,
        completed_at=datetime.now(UTC),
        entities=tuple(
            replace(entity, addressability=classifications.get(entity.value, entity.addressability)) for entity in result.entities
        ),
        dns_validations=(*result.dns_validations, *validation.observations),
    )


async def execute_run(
    target: str,
    sources: Sequence[PassiveSource],
    *,
    dns_validator: DnsValidator | None = None,
    deterministic_exact_dns_names: tuple[str, ...] = (),
) -> RunResult:
    """Collect, normalize, scope, merge, and optionally DNS-validate one run.

    DNS validation is intentionally downstream of provider collection: provider
    observations remain intact even when current DNS disagrees or fails. The
    merged entity receives the consensus classification, while the underlying
    per-resolver answers stay available for audit and later reinterpretation.
    """

    normalized_target = normalize_hostname(target)
    if normalized_target is None:
        raise ValueError('target must be a hostname')
    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    executions: list[SourceExecution] = []
    observations: list[DiscoveryObservation] = []

    for source in sources:
        logger.info(f'Source {source.name} started')
        source_started = time.perf_counter()
        source_observations: tuple[DiscoveryObservation, ...] = ()
        status = SourceStatus.FAILED
        result_count = 0
        error_type: str | None = None
        findings: tuple[SourceFinding, ...] = ()

        try:
            findings = tuple(await source.collect(normalized_target))
            status = SourceStatus.SUCCEEDED
        except SourceIncompleteError as error:
            findings = error.findings
            status = error.status
            error_type = type(error).__name__
        except Exception as error:
            error_type = type(error).__name__
            logger.exception(f'Source {source.name} failed')

        result_count = len(findings)
        try:
            collected_at = datetime.now(UTC)
            normalized_observations = []
            for finding in findings:
                value = normalize_hostname(finding.value)
                if value is None:
                    continue
                normalized_observations.append(
                    DiscoveryObservation(
                        run_id=run_id,
                        target=normalized_target,
                        value=value,
                        source=source.name,
                        source_family=source.family,
                        derivation=finding.derivation,
                        collected_at=collected_at,
                        scope_class=_classify_scope(normalized_target, value, finding.derivation),
                        provider_observed_at=finding.observed_at,
                    )
                )
            source_observations = tuple(normalized_observations)
            if status is SourceStatus.SUCCEEDED and not source_observations:
                status = SourceStatus.EMPTY
        except Exception as error:
            source_observations = ()
            status = SourceStatus.FAILED
            error_type = type(error).__name__
            logger.exception(f'Source {source.name} failed')

        source_entities = _merge_observations(source_observations)
        executions.append(
            SourceExecution(
                run_id=run_id,
                source=source.name,
                source_family=source.family,
                status=status,
                duration_ms=(time.perf_counter() - source_started) * 1000,
                result_count=result_count,
                observation_count=len(source_observations),
                entity_count=len(source_entities),
                error_type=error_type,
            )
        )
        observations.extend(source_observations)
        logger.info(f'Source {source.name} completed with status {status}')

    merged_observations = tuple(observations)
    entities = _merge_observations(merged_observations)
    result = RunResult(
        run_id=run_id,
        target=normalized_target,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        source_executions=tuple(executions),
        observations=merged_observations,
        entities=entities,
    )
    return (
        await validate_run(
            result,
            dns_validator,
            deterministic_exact_dns_names=deterministic_exact_dns_names,
        )
        if dns_validator is not None
        else result
    )


def legacy_hostnames(result: RunResult, source: str | None = None) -> list[str]:
    """Return the host list consumed by the existing CLI, REST, file, and stash paths."""
    validated_hosts = {entity.value for entity in result.entities if entity.addressability is Addressability.CURRENT}
    return sorted(
        {
            observation.value
            for observation in result.observations
            if observation.value != result.target
            and observation.scope_class is ScopeClass.IN_SCOPE
            and (source is None or observation.source == source)
            and (not result.dns_validations or observation.value in validated_hosts)
        }
    )


def legacy_dns_results(result: RunResult, source: str | None = None) -> tuple[list[str], list[str], list[str]]:
    hosts = legacy_hostnames(result, source)
    host_set = set(hosts)
    addresses_by_host: dict[str, set[str]] = {host: set() for host in hosts}
    for observation in result.dns_validations:
        if not observation.is_wildcard_control and observation.candidate in host_set:
            addresses_by_host[observation.candidate].update((*observation.ipv4, *observation.ipv6))
    addresses = sorted({address for values in addresses_by_host.values() for address in values})
    resolved = [f'{host}:{",".join(sorted(addresses_by_host[host]))}' if addresses_by_host[host] else host for host in hosts]
    return resolved, hosts, addresses


def complete_run(result: RunResult, stage_results: Sequence[StageResult] = ()) -> RunResult:
    """Merge selected stage results once and close the run."""
    stage_findings = tuple((stage, finding) for stage in stage_results for finding in dict.fromkeys(stage.findings))
    existing = {(item.source, item.value, item.derivation) for item in result.observations}
    added: list[DiscoveryObservation] = []
    for stage, finding in stage_findings:
        if finding.kind is not StageFindingKind.HOSTNAME:
            continue
        value = normalize_hostname(finding.value.split(':', 1)[0])
        if value is None or (stage.source, value, finding.derivation) in existing:
            continue
        added.append(
            DiscoveryObservation(
                run_id=result.run_id,
                target=result.target,
                value=value,
                source=stage.source,
                source_family=stage.source_family or stage.source,
                derivation=finding.derivation,
                collected_at=stage.completed_at,
                scope_class=_classify_scope(result.target, value, finding.derivation),
            )
        )
        existing.add((stage.source, value, finding.derivation))

    previous_entities = {entity.value: entity for entity in result.entities}
    entities = tuple(
        replace(entity, addressability=previous.addressability)
        if (previous := previous_entities.get(entity.value)) is not None
        else entity
        for entity in _merge_observations((*result.observations, *added))
    )
    selected = tuple(
        SelectedObservation(
            run_id=result.run_id,
            source=stage.source,
            kind=finding.kind,
            value=finding.value,
            detail=finding.detail,
            derivation=finding.derivation,
            collected_at=stage.completed_at,
        )
        for stage, finding in stage_findings
        if finding.kind is not StageFindingKind.HOSTNAME
    )
    executions = list(result.source_executions)
    stage_executions = list(result.stage_executions)
    recorded_sources = {execution.source.casefold(): index for index, execution in enumerate(executions)}
    recorded_stages = {execution.stage.casefold(): index for index, execution in enumerate(stage_executions)}
    for stage in stage_results:
        source_key = stage.source.casefold()
        findings = tuple(dict.fromkeys(stage.findings))
        entity_count = len(
            {
                value
                for finding in findings
                if finding.kind is StageFindingKind.HOSTNAME
                and (value := normalize_hostname(finding.value.split(':', 1)[0])) is not None
            }
        )
        if stage.is_action:
            assert stage.activity_class is not None
            stage_execution = StageExecution(
                run_id=result.run_id,
                stage=stage.source,
                status=stage.status,
                duration_ms=stage.duration_ms,
                result_count=stage.result_count,
                observation_count=len(findings),
                entity_count=entity_count,
                completed_at=stage.completed_at,
                activity_class=stage.activity_class,
                error_type=stage.error_type,
            )
            if source_key in recorded_stages:
                stage_executions[recorded_stages[source_key]] = stage_execution
            else:
                recorded_stages[source_key] = len(stage_executions)
                stage_executions.append(stage_execution)
            continue
        if source_key in recorded_sources:
            index = recorded_sources[source_key]
            execution = executions[index]
            executions[index] = replace(
                execution,
                status=stage.status,
                duration_ms=execution.duration_ms + stage.duration_ms,
                error_type=stage.error_type or execution.error_type,
            )
            continue
        executions.append(
            SourceExecution(
                run_id=result.run_id,
                source=stage.source,
                source_family=stage.source_family or stage.source,
                status=stage.status,
                duration_ms=stage.duration_ms,
                result_count=stage.result_count,
                observation_count=len(findings),
                entity_count=entity_count,
                error_type=stage.error_type,
            )
        )
        recorded_sources[source_key] = len(executions) - 1
    return replace(
        result,
        completed_at=datetime.now(UTC),
        source_executions=tuple(executions),
        stage_executions=tuple(stage_executions),
        observations=(*result.observations, *added),
        entities=entities,
        selected_observations=(*result.selected_observations, *selected),
    )
