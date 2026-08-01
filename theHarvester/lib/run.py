from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from theHarvester.lib.hostnames import normalize_hostname

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)


class ScopeClass(StrEnum):
    IN_SCOPE = 'in-scope'
    OUT_OF_SCOPE = 'out-of-scope'


class SourceStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    EMPTY = 'empty'
    FAILED = 'failed'


class LegacyHostnameSearch(Protocol):
    async def process(self, proxy: bool = False) -> None: ...

    async def get_hostnames(self) -> Iterable[str]: ...


@dataclass(frozen=True)
class LegacyHostnameSource:
    name: str
    search: LegacyHostnameSearch
    proxy: bool = False


@dataclass(frozen=True)
class DiscoveryObservation:
    value: str
    source: str
    scope_class: ScopeClass


@dataclass(frozen=True)
class SourceOutcome:
    source: str
    status: SourceStatus
    process_succeeded: bool
    error_type: str | None = None


@dataclass(frozen=True)
class CollectionResult:
    target: str
    outcome: SourceOutcome
    observations: tuple[DiscoveryObservation, ...]


async def execute_collection(target: str, source: LegacyHostnameSource) -> CollectionResult:
    normalized_target = normalize_hostname(target)
    if normalized_target is None:
        raise ValueError('target must be a hostname')
    normalized_target = normalized_target.removeprefix('www.')
    process_succeeded = False
    try:
        await source.search.process(source.proxy)
        process_succeeded = True
        candidates = tuple(await source.search.get_hostnames())
        observations = tuple(
            DiscoveryObservation(
                value=value,
                source=source.name,
                scope_class=(
                    ScopeClass.IN_SCOPE
                    if value == normalized_target or value.endswith(f'.{normalized_target}')
                    else ScopeClass.OUT_OF_SCOPE
                ),
            )
            for candidate in candidates
            if (value := normalize_hostname(candidate)) is not None
        )
        if candidates and not observations:
            raise ValueError('source returned no usable hostnames')
        status = SourceStatus.SUCCEEDED if observations else SourceStatus.EMPTY
        return CollectionResult(normalized_target, SourceOutcome(source.name, status, True), observations)
    except Exception as error:
        logger.exception(f'Source {source.name} failed')
        return CollectionResult(
            normalized_target,
            SourceOutcome(source.name, SourceStatus.FAILED, process_succeeded, type(error).__name__),
            (),
        )


def legacy_subdomains(result: CollectionResult) -> list[str]:
    """Return in-scope descendants for existing host-compatible consumers."""
    return sorted(
        {
            observation.value
            for observation in result.observations
            if observation.scope_class is ScopeClass.IN_SCOPE and observation.value != result.target
        }
    )
