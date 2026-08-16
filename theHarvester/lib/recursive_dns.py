from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING

from theHarvester.lib.dns_consensus import (
    Addressability,
    BudgetedResolverVantage,
    CandidateConsensus,
    DNSQueryBudget,
    validate_dns_candidates,
)
from theHarvester.lib.hostnames import normalize_scoped_hostname

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from theHarvester.lib.hostchecker import HostDnsRecords


DEFAULT_RECURSIVE_DNS_QUERY_LIMIT = None
DEFAULT_RECURSIVE_DNS_RUNTIME_SECONDS = None


@dataclass(frozen=True, slots=True)
class RecursiveDNSLimits:
    depth: int
    query_limit: int | None = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT
    runtime_seconds: float | None = DEFAULT_RECURSIVE_DNS_RUNTIME_SECONDS

    def __post_init__(self) -> None:
        if self.depth <= 0:
            raise ValueError('recursive DNS depth must be greater than zero')
        if self.query_limit is not None and (
            isinstance(self.query_limit, bool) or not isinstance(self.query_limit, int) or self.query_limit <= 0
        ):
            raise ValueError('recursive DNS query limit must be greater than zero')
        if self.runtime_seconds is not None and (
            isinstance(self.runtime_seconds, bool)
            or not isinstance(self.runtime_seconds, (int, float))
            or not math.isfinite(self.runtime_seconds)
            or self.runtime_seconds <= 0
        ):
            raise ValueError('recursive DNS runtime must be finite and greater than zero')


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


def _normalize_label(value: str) -> str | None:
    label = value.strip().lower()
    if (
        not label
        or '.' in label
        or len(label) > 63
        or label.startswith('-')
        or label.endswith('-')
        or not all(character.isascii() and (character.isalnum() or character in {'-', '_'}) for character in label)
    ):
        return None
    return label


async def discover_recursive_dns(
    target: str,
    seeds: Sequence[str],
    labels: Sequence[str],
    resolvers: Sequence[BudgetedResolverVantage],
    limits: RecursiveDNSLimits,
) -> RecursiveDNSResult:
    normalized_target = target.strip().lower().rstrip('.')
    if not normalized_target:
        raise ValueError('target must not be empty')
    deadline = None if limits.runtime_seconds is None else time.monotonic() + limits.runtime_seconds
    budget = DNSQueryBudget(limits.query_limit)
    stop_reason = 'frontier-exhausted'
    seen: set[str] = set()
    for value in seeds:
        if deadline is not None and time.monotonic() >= deadline:
            stop_reason = 'runtime-limit'
            break
        if (candidate := normalize_scoped_hostname(value, normalized_target)) is not None:
            seen.add(candidate)

    def iter_candidates(parents: Sequence[str]) -> Iterator[tuple[str, str]]:
        nonlocal stop_reason
        seen_labels: set[str] = set()
        ordered_parents = tuple(sorted(parents))
        for value in labels:
            if deadline is not None and time.monotonic() >= deadline:
                stop_reason = 'runtime-limit'
                return
            label = _normalize_label(value)
            if label is None or label in seen_labels:
                continue
            seen_labels.add(label)
            for parent in ordered_parents:
                if deadline is not None and time.monotonic() >= deadline:
                    stop_reason = 'runtime-limit'
                    return
                candidate = f'{label}.{parent}'
                if candidate in seen:
                    continue
                seen.add(candidate)
                yield candidate, parent

    async def validate(candidate: str) -> CandidateConsensus | None:
        nonlocal stop_reason
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            stop_reason = 'runtime-limit'
            return None
        try:
            if remaining is None:
                (consensus,) = await validate_dns_candidates(normalized_target, (candidate,), resolvers, budget=budget)
            else:
                async with asyncio.timeout(remaining):
                    (consensus,) = await validate_dns_candidates(normalized_target, (candidate,), resolvers, budget=budget)
            if budget.blocked:
                stop_reason = 'query-limit'
                return None
            return consensus
        except TimeoutError:
            stop_reason = 'runtime-limit'
            return None

    async def resolve_ptrs(records: HostDnsRecords) -> tuple[str, ...]:
        nonlocal stop_reason
        ptrs: set[str] = set()
        for address in records.addresses:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                stop_reason = 'runtime-limit'
                break
            try:
                queries = asyncio.gather(*(resolver.query_ptr(address, budget) for resolver in resolvers), return_exceptions=True)
                results = await queries if remaining is None else await asyncio.wait_for(queries, remaining)
            except TimeoutError:
                stop_reason = 'runtime-limit'
                break
            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if not isinstance(result, BaseException):
                    ptrs.update(result)
            if budget.blocked:
                stop_reason = 'query-limit'
                break
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
    depth_reached = 0
    stopped = stop_reason in {'query-limit', 'runtime-limit'}
    for depth in range(1, limits.depth + 1):
        if stopped or not frontier:
            break
        next_frontier: list[str] = []
        candidates = iter_candidates(frontier)
        while batch := tuple(islice(candidates, 50)):
            batch_yield = 0
            for candidate, parent in batch:
                consensus = await validate(candidate)
                if consensus is None:
                    stopped = True
                    break
                depth_reached = depth
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
            if not batch_yield:
                zero_yield_batches += 1
        if stop_reason in {'query-limit', 'runtime-limit'}:
            stopped = True
        if stopped:
            break
        frontier = next_frontier
        if not frontier:
            stop_reason = 'frontier-exhausted'
            break
    else:
        stop_reason = 'depth-limit'
    return RecursiveDNSResult(
        tuple(findings), budget.used, depth_reached, zero_yield_batches, stop_reason, tuple(classifications)
    )
