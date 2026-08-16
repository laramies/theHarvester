"""Classify hostnames by comparing three resolvers with wildcard controls."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast
from uuid import uuid4

import aiodns

from theHarvester.lib.hostchecker import HostDnsRecords
from theHarvester.lib.hostnames import normalize_scoped_hostname

if TYPE_CHECKING:
    from collections.abc import Sequence


class Addressability(StrEnum):
    """DNS classification assigned to a candidate hostname."""

    CURRENT = 'currently-addressable'
    NOT_CURRENT = 'not-currently-addressable'
    RESOLVER_DISPUTED = 'resolver-disputed'
    WILDCARD_INDISTINGUISHABLE = 'wildcard-indistinguishable'


@dataclass(slots=True)
class DNSQueryBudget:
    limit: int | None
    used: int = 0
    blocked: bool = False

    def __post_init__(self) -> None:
        if self.limit is not None and self.limit <= 0:
            raise ValueError('DNS query budget must be greater than zero')

    def consume(self, count: int) -> bool:
        if count <= 0:
            raise ValueError('DNS query count must be greater than zero')
        if self.limit is not None and self.used + count > self.limit:
            self.blocked = True
            return False
        self.used += count
        return True


@dataclass(frozen=True, slots=True)
class DNSResponse:
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    rcode: str = 'NOERROR'
    error: str | None = None

    @property
    def records(self) -> HostDnsRecords:
        return HostDnsRecords(self.ipv4, self.ipv6, self.cnames)


class ResolverVantage(Protocol):
    name: str

    async def query(self, hostname: str) -> DNSResponse: ...


class BudgetedResolverVantage(ResolverVantage, Protocol):
    async def query(self, hostname: str, budget: DNSQueryBudget | None = None) -> DNSResponse: ...

    async def query_ptr(self, address: str, budget: DNSQueryBudget | None = None) -> tuple[str, ...]: ...


class AioDNSResolverVantage:
    """Query one nameserver and follow CNAMEs that remain under the target."""

    def __init__(self, nameserver: str, target: str) -> None:
        self.name = nameserver
        self._target = target
        self._resolver = aiodns.DNSResolver(nameservers=[nameserver])

    async def query(self, hostname: str, budget: DNSQueryBudget | None = None) -> DNSResponse:
        current = hostname.strip().lower().rstrip('.')
        seen = {current}
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        cnames: list[str] = []
        dns_errors: list[int] = []
        errors: list[str] = []
        successful_query = False
        for _ in range(16):
            if budget is not None and not budget.consume(3):
                errors.append('query-limit')
                break
            results = await asyncio.gather(
                *(self._resolver.query_dns(current, record_type) for record_type in ('A', 'AAAA', 'CNAME')),
                return_exceptions=True,
            )
            next_cnames: list[str] = []
            for record_type, result in zip(('A', 'AAAA', 'CNAME'), results, strict=True):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, BaseException):
                    if isinstance(result, aiodns.error.DNSError):
                        dns_errors.append(result.args[0])
                        if result.args[0] in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA}:
                            continue
                    errors.append(type(result).__name__)
                    continue
                successful_query = True
                for record in result.answer:
                    if record_type == 'CNAME':
                        value = getattr(record.data, 'cname', None)
                        if isinstance(value, str) and (normalized := value.strip().lower().rstrip('.')):
                            next_cnames.append(normalized)
                        continue
                    value = getattr(record.data, 'addr', None)
                    if not isinstance(value, str):
                        continue
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    if address.version == (4 if record_type == 'A' else 6):
                        (ipv4 if address.version == 4 else ipv6).add(str(address))
            if not next_cnames:
                break
            for cname in next_cnames:
                if cname not in cnames:
                    cnames.append(cname)
            current = next_cnames[-1]
            if normalize_scoped_hostname(current, self._target) is None:
                break
            if current in seen:
                errors.append(f'CNAME loop detected at {current}')
                break
            seen.add(current)
        else:
            errors.append('CNAME chain exceeded 16 links')
        if successful_query:
            rcode = 'NOERROR'
        elif dns_errors and all(code == aiodns.error.ARES_ENOTFOUND for code in dns_errors):
            rcode = 'NXDOMAIN'
        elif dns_errors and all(code in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA} for code in dns_errors):
            rcode = 'NODATA'
        else:
            rcode = 'ERROR'
        return DNSResponse(
            ipv4=tuple(sorted(ipv4)),
            ipv6=tuple(sorted(ipv6)),
            cnames=tuple(cnames),
            rcode=rcode,
            error='; '.join(errors) or None,
        )

    async def query_ptr(self, address: str, budget: DNSQueryBudget | None = None) -> tuple[str, ...]:
        try:
            reverse_pointer = ipaddress.ip_address(address).reverse_pointer
        except ValueError:
            return ()
        if budget is not None and not budget.consume(1):
            return ()
        try:
            result = await self._resolver.query_dns(reverse_pointer, 'PTR')
        except asyncio.CancelledError:
            raise
        except aiodns.error.DNSError:
            return ()
        return tuple(
            sorted(
                {
                    normalized
                    for record in result.answer
                    if isinstance(value := getattr(record.data, 'dname', None), str)
                    and (normalized := value.strip().lower().rstrip('.'))
                }
            )
        )

    async def close(self) -> None:
        await self._resolver.close()


@dataclass(frozen=True, slots=True)
class DNSValidation:
    query_name: str
    resolver: str
    response: DNSResponse
    wildcard_depth: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateConsensus:
    """Classification and resolver evidence for one candidate hostname."""

    hostname: str
    addressability: Addressability
    validations: tuple[DNSValidation, ...]

    @property
    def records(self) -> HostDnsRecords:
        candidate_responses = (item.response for item in self.validations if item.wildcard_depth is None)
        return HostDnsRecords(
            ipv4=tuple(sorted({value for response in candidate_responses for value in response.ipv4})),
            ipv6=tuple(
                sorted({value for item in self.validations if item.wildcard_depth is None for value in item.response.ipv6})
            ),
            cnames=tuple(
                sorted({value for item in self.validations if item.wildcard_depth is None for value in item.response.cnames})
            ),
        )


def _normalize_response(response: DNSResponse) -> DNSResponse:
    return DNSResponse(
        ipv4=tuple(sorted({str(ipaddress.IPv4Address(value)) for value in response.ipv4})),
        ipv6=tuple(sorted({str(ipaddress.IPv6Address(value)) for value in response.ipv6})),
        cnames=tuple(sorted({value.strip().lower().rstrip('.') for value in response.cnames if value.strip()})),
        rcode=response.rcode.upper(),
        error=response.error,
    )


async def _query(
    query_name: str,
    resolver: ResolverVantage,
    *,
    wildcard_depth: str | None = None,
    budget: DNSQueryBudget | None = None,
) -> DNSValidation:
    try:
        if budget is None:
            response = await resolver.query(query_name)
        else:
            response = await cast('BudgetedResolverVantage', resolver).query(query_name, budget)
        response = _normalize_response(response)
    except asyncio.CancelledError:
        raise
    except Exception as error:
        response = DNSResponse(rcode='ERROR', error=type(error).__name__)
    return DNSValidation(query_name, resolver.name, response, wildcard_depth)


def _wildcard_depths(target: str, candidate: str) -> tuple[str, ...]:
    target_labels = target.split('.')
    candidate_labels = candidate.split('.')
    extra_label_count = len(candidate_labels) - len(target_labels)
    return (target, *('.'.join(candidate_labels[index:]) for index in range(extra_label_count - 1, 0, -1)))


def _has_records(validation: DNSValidation) -> bool:
    return bool(validation.response.records.addresses or validation.response.records.cnames)


def _has_address(validation: DNSValidation) -> bool:
    return bool(validation.response.records.addresses)


def _response_signature(validation: DNSValidation) -> HostDnsRecords:
    return validation.response.records


def _classify(validations: Sequence[DNSValidation]) -> Addressability:
    candidates = tuple(item for item in validations if item.wildcard_depth is None)
    controls = tuple(item for item in validations if item.wildcard_depth is not None)
    closest_depth = max((item.wildcard_depth for item in controls if item.wildcard_depth), key=lambda value: value.count('.'))
    candidate_signatures = {_response_signature(item) for item in candidates if _has_records(item)}
    control_signatures = {
        _response_signature(item) for item in controls if item.wildcard_depth == closest_depth and _has_records(item)
    }
    if candidate_signatures & control_signatures:
        return Addressability.WILDCARD_INDISTINGUISHABLE
    if sum(map(_has_address, candidates)) >= 2:
        return Addressability.CURRENT
    negatives = sum(
        not _has_address(item) and item.response.error is None and item.response.rcode in {'NOERROR', 'NXDOMAIN', 'NODATA'}
        for item in candidates
    )
    return Addressability.NOT_CURRENT if negatives >= 2 else Addressability.RESOLVER_DISPUTED


async def validate_dns_candidates(
    target: str,
    candidates: Sequence[str],
    resolvers: Sequence[ResolverVantage],
    *,
    budget: DNSQueryBudget | None = None,
) -> tuple[CandidateConsensus, ...]:
    """Compare each in-scope candidate with randomized wildcard controls.

    A candidate is current when at least two of the three resolvers return an
    address and its records do not match the closest wildcard control.
    """
    normalized_target = target.strip().lower().rstrip('.')
    if not normalized_target:
        raise ValueError('target must not be empty')
    resolver_identities = []
    for resolver in resolvers:
        try:
            resolver_identities.append(str(ipaddress.ip_address(resolver.name)))
        except ValueError:
            resolver_identities.append(resolver.name)
    if len(resolvers) != 3 or len(set(resolver_identities)) != 3:
        raise ValueError('DNS consensus requires exactly three distinct resolver vantages')
    results: list[CandidateConsensus] = []
    normalized_candidates = tuple(
        dict.fromkeys(
            candidate for value in candidates if (candidate := normalize_scoped_hostname(value, normalized_target)) is not None
        )
    )
    for candidate in normalized_candidates:
        controls = tuple(
            (f'th-{uuid4().hex}.{depth}', depth) for depth in _wildcard_depths(normalized_target, candidate) for _ in range(3)
        )
        validations = tuple(
            await asyncio.gather(
                *(_query(candidate, resolver, budget=budget) for resolver in resolvers),
                *(
                    _query(query_name, resolver, wildcard_depth=depth, budget=budget)
                    for query_name, depth in controls
                    for resolver in resolvers
                ),
            )
        )
        addressability = Addressability.RESOLVER_DISPUTED if budget is not None and budget.blocked else _classify(validations)
        results.append(CandidateConsensus(candidate, addressability, validations))
    return tuple(results)
