from __future__ import annotations

import logging
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

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
    EMPTY = 'empty'
    FAILED = 'failed'
    RATE_LIMITED = 'rate-limited'


@dataclass(frozen=True)
class SourceFinding:
    value: str
    derivation: Derivation = Derivation.PROVIDER


class SourceIncompleteError(Exception):
    status = SourceStatus.FAILED

    def __init__(self, message: str = '', *, findings: Sequence[SourceFinding] = ()) -> None:
        super().__init__(message)
        self.findings = tuple(findings)


class SourceRateLimitedError(SourceIncompleteError):
    status = SourceStatus.RATE_LIMITED


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
    run_id: str
    target: str
    value: str
    source: str
    source_family: str
    derivation: Derivation
    collected_at: datetime
    scope_class: ScopeClass


@dataclass(frozen=True)
class SourceExecution:
    run_id: str
    source: str
    source_family: str
    status: SourceStatus
    duration_ms: float
    result_count: int
    observation_count: int
    entity_count: int
    error_type: str | None = None


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
        return len({observation.source_family for observation in self.observations})


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


async def execute_run(
    target: str,
    sources: Sequence[PassiveSource],
    *,
    dns_validator: DnsValidator | None = None,
    deterministic_exact_dns_names: tuple[str, ...] = (),
) -> RunResult:
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
    dns_validations: tuple[DnsValidationObservation, ...] = ()
    if dns_validator is not None:
        validation = await dns_validator.validate(
            run_id,
            normalized_target,
            tuple(entity.value for entity in entities if ScopeClass.IN_SCOPE in entity.scope_classes),
            deterministic_exact_names=deterministic_exact_dns_names,
        )
        classifications = {
            classification.candidate: classification.addressability for classification in validation.classifications
        }
        entities = tuple(replace(entity, addressability=classifications.get(entity.value)) for entity in entities)
        dns_validations = validation.observations

    result = RunResult(
        run_id=run_id,
        target=normalized_target,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        source_executions=tuple(executions),
        observations=merged_observations,
        entities=entities,
        dns_validations=dns_validations,
    )
    return result


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
