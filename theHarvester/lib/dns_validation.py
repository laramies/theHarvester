from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

import aiodns

from theHarvester.lib.hostnames import normalize_hostname, normalize_scoped_hostname

_RESOLVER_COUNT = 3
_RESOLVER_QUORUM = 2
_PROBES_PER_DEPTH = 3
_DEFAULT_QUERY_TIMEOUT_SECONDS = 10.0


class Addressability(StrEnum):
    CURRENT = 'currently-addressable'
    NOT_CURRENT = 'not-currently-addressable'
    RESOLVER_DISPUTED = 'resolver-disputed'
    WILDCARD_INDISTINGUISHABLE = 'wildcard-indistinguishable'


@dataclass(frozen=True)
class DnsResponse:
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    rcode: str = 'NOERROR'
    ttl: int | None = None
    cname_chain: tuple[str, ...] = ()
    error: str | None = None


class ResolverVantage(Protocol):
    name: str

    async def query(self, hostname: str) -> DnsResponse: ...


class AioDnsResolverVantage:
    def __init__(self, nameserver: str) -> None:
        self.name = nameserver
        self._resolver = aiodns.DNSResolver(nameservers=[nameserver])

    async def query(self, hostname: str) -> DnsResponse:
        record_types = ('A', 'AAAA', 'CNAME')
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        cnames: list[str] = []
        ttls: list[int] = []
        dns_error_codes: list[int] = []
        errors: list[str] = []
        successful_query = False
        query_name = normalize_hostname(hostname)
        if query_name is None:
            return DnsResponse(rcode='ERROR', error='invalid hostname')

        results = await asyncio.gather(
            *(self._resolver.query_dns(query_name, record_type) for record_type in record_types),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, aiodns.error.DNSError):
                code = result.args[0]
                dns_error_codes.append(code)
                if code not in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA}:
                    errors.append(f'{type(result).__name__}: {result}')
                continue
            if isinstance(result, BaseException):
                raise result
            successful_query = True
            for record in result.answer:
                if (ttl := getattr(record, 'ttl', None)) is not None:
                    ttls.append(ttl)
                if (address := getattr(record.data, 'addr', None)) is not None:
                    try:
                        parsed = ipaddress.ip_address(address)
                    except ValueError:
                        errors.append(f'invalid address: {address}')
                    else:
                        (ipv4 if parsed.version == 4 else ipv6).add(str(parsed))
                if (cname := getattr(record.data, 'cname', None)) is not None:
                    if (normalized := normalize_hostname(cname)) is not None and normalized not in cnames:
                        cnames.append(normalized)

        if successful_query:
            rcode = 'NOERROR'
        elif dns_error_codes and all(code == aiodns.error.ARES_ENOTFOUND for code in dns_error_codes):
            rcode = 'NXDOMAIN'
        elif dns_error_codes and all(
            code in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA} for code in dns_error_codes
        ):
            rcode = 'NODATA'
        else:
            rcode = 'ERROR'
        return DnsResponse(
            ipv4=tuple(sorted(ipv4)),
            ipv6=tuple(sorted(ipv6)),
            cnames=tuple(cnames),
            rcode=rcode,
            ttl=min(ttls, default=None),
            cname_chain=tuple(cnames),
            error='; '.join(errors) or None,
        )

    async def close(self) -> None:
        await self._resolver.close()


@dataclass(frozen=True)
class DnsValidationObservation:
    run_id: str
    candidate: str | None
    query_name: str
    resolver: str
    queried_at: datetime
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    cnames: tuple[str, ...]
    rcode: str
    ttl: int | None
    cname_chain: tuple[str, ...]
    latency_ms: float
    error: str | None
    is_wildcard_control: bool = False
    wildcard_depth: str | None = None


@dataclass(frozen=True)
class CandidateClassification:
    candidate: str
    addressability: Addressability


@dataclass(frozen=True)
class ValidationResult:
    observations: tuple[DnsValidationObservation, ...]
    classifications: tuple[CandidateClassification, ...]


def _normalize_response(response: DnsResponse) -> DnsResponse:
    return DnsResponse(
        ipv4=tuple(sorted({str(ipaddress.IPv4Address(value)) for value in response.ipv4})),
        ipv6=tuple(sorted({str(ipaddress.IPv6Address(value)) for value in response.ipv6})),
        cnames=tuple(sorted(normalized for value in response.cnames if (normalized := normalize_hostname(value)) is not None)),
        rcode=response.rcode.upper(),
        ttl=response.ttl,
        cname_chain=tuple(normalized for value in response.cname_chain if (normalized := normalize_hostname(value)) is not None),
        error=response.error,
    )


def _wildcard_depths(target: str, candidate: str) -> tuple[str, ...]:
    target_labels = target.split('.')
    candidate_labels = candidate.split('.')
    extra_labels = len(candidate_labels) - len(target_labels)
    return (target, *('.'.join(candidate_labels[index:]) for index in range(extra_labels - 1, 0, -1)))


def _has_dns_evidence(observation: DnsValidationObservation) -> bool:
    return bool(observation.ipv4 or observation.ipv6 or observation.cnames or observation.cname_chain)


def _signature(observation: DnsValidationObservation) -> tuple[object, ...]:
    return (
        observation.rcode,
        observation.ipv4,
        observation.ipv6,
        observation.cnames,
        observation.cname_chain,
    )


def _record_presence_signature(observation: DnsValidationObservation) -> tuple[object, ...]:
    return (
        observation.rcode,
        bool(observation.ipv4),
        bool(observation.ipv6),
        bool(observation.cnames or observation.cname_chain),
    )


def _overlaps_wildcard(
    candidate_observations: tuple[DnsValidationObservation, ...],
    controls: tuple[DnsValidationObservation, ...],
) -> bool:
    candidate_evidence = tuple(observation for observation in candidate_observations if _has_dns_evidence(observation))
    control_evidence = tuple(observation for observation in controls if _has_dns_evidence(observation))
    if not candidate_evidence or not control_evidence:
        return False
    signatures = {_signature(observation) for observation in control_evidence}
    if any(_signature(observation) in signatures for observation in candidate_evidence):
        return True
    return len(signatures) > 1 and any(
        _record_presence_signature(observation) in {_record_presence_signature(control) for control in control_evidence}
        for observation in candidate_evidence
    )


def _classify(
    candidate_observations: tuple[DnsValidationObservation, ...],
    controls: tuple[DnsValidationObservation, ...],
    *,
    deterministic_exact: bool,
) -> Addressability:
    if not deterministic_exact and _overlaps_wildcard(candidate_observations, controls):
        return Addressability.WILDCARD_INDISTINGUISHABLE
    addressable = sum(
        observation.rcode == 'NOERROR' and bool(observation.ipv4 or observation.ipv6) for observation in candidate_observations
    )
    not_addressable = sum(
        observation.error is None
        and not observation.ipv4
        and not observation.ipv6
        and observation.rcode in {'NOERROR', 'NXDOMAIN', 'NODATA'}
        for observation in candidate_observations
    )
    if addressable >= _RESOLVER_QUORUM:
        return Addressability.CURRENT
    if not_addressable >= _RESOLVER_QUORUM:
        return Addressability.NOT_CURRENT
    return Addressability.RESOLVER_DISPUTED


class DnsValidator:
    def __init__(
        self,
        vantages: tuple[ResolverVantage, ...],
        *,
        timeout_seconds: float = _DEFAULT_QUERY_TIMEOUT_SECONDS,
    ) -> None:
        if len(vantages) != _RESOLVER_COUNT or len({vantage.name for vantage in vantages}) != _RESOLVER_COUNT:
            raise ValueError('DNS validation requires exactly three distinct resolver vantages')
        if timeout_seconds <= 0:
            raise ValueError('DNS validation timeout must be positive')
        self.vantages = vantages
        self.timeout_seconds = timeout_seconds

    async def _query(
        self,
        run_id: str,
        query_name: str,
        *,
        candidate: str | None = None,
        wildcard_depth: str | None = None,
    ) -> tuple[DnsValidationObservation, ...]:
        async def query(vantage: ResolverVantage) -> DnsValidationObservation:
            queried_at = datetime.now(UTC)
            started = time.perf_counter()
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    response = _normalize_response(await vantage.query(query_name))
            except Exception as error:
                response = DnsResponse(rcode='ERROR', error=f'{type(error).__name__}: {error}')
            return DnsValidationObservation(
                run_id=run_id,
                candidate=candidate,
                query_name=query_name,
                resolver=vantage.name,
                queried_at=queried_at,
                ipv4=response.ipv4,
                ipv6=response.ipv6,
                cnames=response.cnames,
                rcode=response.rcode,
                ttl=response.ttl,
                cname_chain=response.cname_chain,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=response.error,
                is_wildcard_control=wildcard_depth is not None,
                wildcard_depth=wildcard_depth,
            )

        return tuple(await asyncio.gather(*(query(vantage) for vantage in self.vantages)))

    async def validate(
        self,
        run_id: str,
        target: str,
        candidates: tuple[str, ...],
        *,
        deterministic_exact_names: tuple[str, ...] = (),
    ) -> ValidationResult:
        """Trust deterministic_exact_names only as caller-supplied exact-node evidence."""
        normalized_target = normalize_hostname(target)
        if normalized_target is None:
            raise ValueError('target must be a hostname')
        normalized_candidates = tuple(
            dict.fromkeys(
                normalized
                for candidate in candidates
                if (normalized := normalize_scoped_hostname(candidate, normalized_target)) is not None
                and normalized != normalized_target
            )
        )
        normalized_deterministic_exact_names = {
            normalized
            for name in deterministic_exact_names
            if (normalized := normalize_scoped_hostname(name, normalized_target)) is not None
        }

        candidate_observations: dict[str, tuple[DnsValidationObservation, ...]] = {}
        observations: list[DnsValidationObservation] = []
        for candidate in normalized_candidates:
            candidate_observations[candidate] = await self._query(run_id, candidate, candidate=candidate)
            observations.extend(candidate_observations[candidate])

        depths = tuple(
            dict.fromkeys(
                depth for candidate in normalized_candidates for depth in _wildcard_depths(normalized_target, candidate)
            )
        )
        controls_by_depth: dict[str, list[DnsValidationObservation]] = {depth: [] for depth in depths}
        for depth in depths:
            for _ in range(_PROBES_PER_DEPTH):
                query_name = f'th-{uuid4().hex}.{depth}'
                controls = await self._query(run_id, query_name, wildcard_depth=depth)
                controls_by_depth[depth].extend(controls)
                observations.extend(controls)

        classifications = []
        for candidate in normalized_candidates:
            closest_depth = _wildcard_depths(normalized_target, candidate)[-1]
            classifications.append(
                CandidateClassification(
                    candidate,
                    _classify(
                        candidate_observations[candidate],
                        tuple(controls_by_depth[closest_depth]),
                        deterministic_exact=candidate in normalized_deterministic_exact_names,
                    ),
                )
            )
        return ValidationResult(tuple(observations), tuple(classifications))
