from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from theHarvester.lib.dns_consensus import Addressability, CandidateConsensus, ResolverVantage, validate_dns_candidates
from theHarvester.lib.hostnames import normalize_scoped_hostname

if TYPE_CHECKING:
    from collections.abc import Sequence

    from theHarvester.lib.hostchecker import HostDnsRecords


DEFAULT_RECURSIVE_DNS_QUERY_LIMIT = 1_000


@dataclass(frozen=True, slots=True)
class RecursiveDNSLimits:
    depth: int
    query_limit: int
    runtime_seconds: float

    def __post_init__(self) -> None:
        if self.depth <= 0:
            raise ValueError('recursive DNS depth must be greater than zero')
        if self.query_limit <= 0:
            raise ValueError('recursive DNS query limit must be greater than zero')
        if self.runtime_seconds <= 0:
            raise ValueError('recursive DNS runtime must be greater than zero')


@dataclass(frozen=True, slots=True)
class RecursiveDNSFinding:
    hostname: str
    parent: str
    records: HostDnsRecords
    ptrs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecursiveDNSClassification:
    hostname: str
    parent: str
    addressability: Addressability
    records: HostDnsRecords
    ptrs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecursiveDNSResult:
    findings: tuple[RecursiveDNSFinding, ...]
    query_count: int
    depth_reached: int
    zero_yield_batches: int
    stop_reason: str
    classifications: tuple[RecursiveDNSClassification, ...] = ()


def _query_cost(target: str, candidate: str) -> int:
    wildcard_depths = max(1, len(candidate.split('.')) - len(target.split('.')))
    return 3 + wildcard_depths * 9


def _normalize_labels(labels: Sequence[str], deadline: float) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in labels:
        if time.monotonic() >= deadline:
            break
        label = value.strip().lower()
        if (
            not label
            or '.' in label
            or len(label) > 63
            or label.startswith('-')
            or label.endswith('-')
            or not all(character.isascii() and (character.isalnum() or character in {'-', '_'}) for character in label)
        ):
            continue
        normalized.append(label)
    return tuple(dict.fromkeys(normalized))


async def discover_recursive_dns(
    target: str,
    seeds: Sequence[str],
    labels: Sequence[str],
    resolvers: Sequence[ResolverVantage],
    limits: RecursiveDNSLimits,
) -> RecursiveDNSResult:
    normalized_target = target.strip().lower().rstrip('.')
    if not normalized_target:
        raise ValueError('target must not be empty')
    started = time.monotonic()
    deadline = started + limits.runtime_seconds
    normalized_labels = _normalize_labels(labels, deadline)
    seen = {candidate for value in seeds if (candidate := normalize_scoped_hostname(value, normalized_target)) is not None}
    query_count = 0
    stop_reason = 'frontier-exhausted'

    async def validate(candidate: str) -> CandidateConsensus | None:
        nonlocal query_count, stop_reason
        query_cost = _query_cost(normalized_target, candidate)
        if query_count + query_cost > limits.query_limit:
            stop_reason = 'query-limit'
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_reason = 'runtime-limit'
            return None
        query_count += query_cost
        try:
            async with asyncio.timeout(remaining):
                (consensus,) = await validate_dns_candidates(normalized_target, (candidate,), resolvers)
                return consensus
        except TimeoutError:
            stop_reason = 'runtime-limit'
            return None

    async def resolve_ptrs(records: HostDnsRecords) -> tuple[str, ...]:
        nonlocal query_count, stop_reason
        ptrs: set[str] = set()
        for address in records.addresses:
            query_cost = len(resolvers)
            if query_count + query_cost > limits.query_limit:
                stop_reason = 'query-limit'
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_reason = 'runtime-limit'
                break
            query_count += query_cost
            try:
                async with asyncio.timeout(remaining):
                    results = await asyncio.gather(
                        *(resolver.query_ptr(address) for resolver in resolvers), return_exceptions=True
                    )
            except TimeoutError:
                stop_reason = 'runtime-limit'
                break
            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if not isinstance(result, BaseException):
                    ptrs.update(result)
        return tuple(sorted(ptrs))

    frontier: list[str] = []
    for seed in sorted(seen):
        consensus = await validate(seed)
        if consensus is None:
            break
        if consensus.addressability is Addressability.CURRENT:
            frontier.append(seed)

    findings: list[RecursiveDNSFinding] = []
    classifications: list[RecursiveDNSClassification] = []
    zero_yield_batches = 0
    consecutive_zero_yield_batches = 0
    depth_reached = 0
    stopped = stop_reason in {'query-limit', 'runtime-limit'}
    for depth in range(1, limits.depth + 1):
        if stopped or not frontier:
            break
        candidates = [
            (f'{label}.{parent}', parent)
            for parent in sorted(frontier)
            for label in normalized_labels
            if f'{label}.{parent}' not in seen
        ]
        seen.update(candidate for candidate, _parent in candidates)
        next_frontier: list[str] = []
        for offset in range(0, len(candidates), 50):
            batch_yield = 0
            for candidate, parent in candidates[offset : offset + 50]:
                consensus = await validate(candidate)
                if consensus is None:
                    stopped = True
                    break
                ptrs = await resolve_ptrs(consensus.records) if consensus.addressability is Addressability.CURRENT else ()
                if (
                    consensus.addressability is not Addressability.NOT_CURRENT
                    or (consensus.records.addresses or consensus.records.cnames)
                    or any(
                        validation.wildcard_depth is None
                        and validation.response.error is None
                        and validation.response.rcode in {'NOERROR', 'NODATA'}
                        for validation in consensus.validations
                    )
                ):
                    classifications.append(
                        RecursiveDNSClassification(candidate, parent, consensus.addressability, consensus.records, ptrs)
                    )
                if consensus.addressability is Addressability.CURRENT:
                    findings.append(RecursiveDNSFinding(candidate, parent, consensus.records, ptrs))
                    next_frontier.append(candidate)
                    batch_yield += 1
                if stop_reason in {'query-limit', 'runtime-limit'}:
                    stopped = True
                    break
            if stopped:
                break
            if batch_yield:
                consecutive_zero_yield_batches = 0
            else:
                consecutive_zero_yield_batches += 1
                zero_yield_batches += 1
                if consecutive_zero_yield_batches >= 3:
                    stop_reason = 'zero-yield'
                    stopped = True
                    break
        if stopped:
            break
        depth_reached = depth
        frontier = next_frontier
        if not frontier:
            stop_reason = 'frontier-exhausted'
            break
    else:
        stop_reason = 'depth-limit'
    return RecursiveDNSResult(
        tuple(findings), query_count, depth_reached, zero_yield_batches, stop_reason, tuple(classifications)
    )
