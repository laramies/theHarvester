"""Probe authorized IP endpoints for virtual hosts without resolving candidate names."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import math
import re
import secrets
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal, Self, cast
from urllib.parse import urlsplit

import aiohttp

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Mapping

ProbePhase = Literal['connect', 'tls', 'headers', 'body']
VirtualHostClassification = Literal['distinct', 'default', 'indeterminate']
DEFAULT_VHOST_CONCURRENCY = 5
DEFAULT_VHOST_REQUEST_LIMIT = 100
DEFAULT_VHOST_RUNTIME_SECONDS = 30.0
DEFAULT_VHOST_TIMEOUT_SECONDS = 5.0
VHOST_BODY_LIMIT = 1024 * 1024
VHOST_CONTROL_COUNT = 3
VHOST_BASELINE_REQUEST_COUNT = 1 + VHOST_CONTROL_COUNT


@dataclass(frozen=True, slots=True)
class VirtualHostLimits:
    request_limit: int = DEFAULT_VHOST_REQUEST_LIMIT
    runtime_seconds: float = DEFAULT_VHOST_RUNTIME_SECONDS
    timeout_seconds: float = DEFAULT_VHOST_TIMEOUT_SECONDS
    concurrency: int = DEFAULT_VHOST_CONCURRENCY

    def __post_init__(self) -> None:
        if isinstance(self.request_limit, bool) or not isinstance(self.request_limit, int):
            raise ValueError('virtual-host request limit must be an integer')
        if isinstance(self.concurrency, bool) or not isinstance(self.concurrency, int):
            raise ValueError('virtual-host concurrency must be an integer')
        if self.request_limit <= VHOST_BASELINE_REQUEST_COUNT:
            raise ValueError(f'virtual-host request limit must be greater than {VHOST_BASELINE_REQUEST_COUNT}')
        if (
            isinstance(self.runtime_seconds, bool)
            or not isinstance(self.runtime_seconds, int | float)
            or not math.isfinite(self.runtime_seconds)
            or self.runtime_seconds <= 0
        ):
            raise ValueError('virtual-host runtime seconds must be positive and finite')
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError('virtual-host timeout seconds must be positive and finite')
        if self.concurrency <= 0:
            raise ValueError('virtual-host concurrency must be positive')


def normalize_virtual_host_hostname(value: str) -> str:
    hostname = value.strip().rstrip('.').lower()
    if not hostname:
        raise ValueError('virtual-host candidate must not be empty')
    try:
        hostname = hostname.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise ValueError('virtual-host candidate must be a valid hostname') from error
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError('virtual-host candidate must be a hostname, not an IP address')
    labels = hostname.split('.')
    if len(hostname) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith('-')
        or label.endswith('-')
        or not all(character.isalnum() or character == '-' for character in label)
        for label in labels
    ):
        raise ValueError('virtual-host candidate must be a valid hostname')
    return hostname


def _candidate_shape(candidate: str, scope: str) -> tuple[int, ...]:
    if candidate == scope:
        return (1,)
    relative_name = candidate[: -(len(scope) + 1)]
    return tuple(len(label) for label in relative_name.split('.'))


def normalize_virtual_host_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('virtual-host endpoint scheme must be http or https')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('virtual-host endpoint must not contain user information')
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('virtual-host endpoint must contain only scheme, literal IP, and optional port')
    try:
        address = ipaddress.ip_address(parsed.hostname or '')
    except ValueError as error:
        raise ValueError('virtual-host endpoint must use a literal IP address') from error
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    except ValueError as error:
        raise ValueError('virtual-host endpoint port must be between 1 and 65535') from error
    if not 1 <= port <= 65535:
        raise ValueError('virtual-host endpoint port must be between 1 and 65535')
    authority = f'[{address.compressed}]' if address.version == 6 else address.compressed
    return f'{parsed.scheme}://{authority}:{port}/'


def normalize_virtual_host_candidates(scope: str, candidates: tuple[str, ...]) -> tuple[str, ...]:
    normalized_scope = normalize_virtual_host_hostname(scope)
    normalized_candidates: list[str] = []
    for candidate in candidates:
        normalized = normalize_virtual_host_hostname(candidate)
        if normalized != normalized_scope and not normalized.endswith(f'.{normalized_scope}'):
            raise ValueError(f'virtual-host candidate is outside authorized scope: {candidate}')
        if normalized not in normalized_candidates:
            normalized_candidates.append(normalized)
    return tuple(normalized_candidates)


@dataclass(frozen=True, slots=True, init=False)
class VirtualHostRequest:
    endpoint: str
    scope: str
    candidates: tuple[str, ...]
    limits: VirtualHostLimits
    insecure: bool

    def __init__(
        self,
        *,
        endpoint: str,
        scope: str,
        candidates: tuple[str, ...],
        limits: VirtualHostLimits | None = None,
        insecure: bool = False,
    ) -> None:
        normalized_endpoint = normalize_virtual_host_endpoint(endpoint)
        normalized_scope = normalize_virtual_host_hostname(scope)
        normalized_candidates = normalize_virtual_host_candidates(normalized_scope, candidates)
        if not normalized_candidates:
            raise ValueError('virtual-host discovery requires at least one candidate')
        normalized_limits = limits if limits is not None else VirtualHostLimits()
        if not isinstance(normalized_limits, VirtualHostLimits):
            raise ValueError('virtual-host limits must be VirtualHostLimits')
        if not isinstance(insecure, bool):
            raise ValueError('virtual-host insecure must be a boolean')
        shape_counts: dict[tuple[int, ...], int] = {}
        for candidate in normalized_candidates:
            shape = _candidate_shape(candidate, normalized_scope)
            if candidate != normalized_scope:
                shape_counts[shape] = shape_counts.get(shape, 0) + 1
            else:
                shape_counts.setdefault(shape, 0)
        for shape, candidate_count in shape_counts.items():
            if 36 ** sum(shape) - candidate_count < VHOST_CONTROL_COUNT:
                raise ValueError('virtual-host candidate shape leaves fewer than three available unknown controls')
        control_shape_count = len(shape_counts)
        minimum_request_count = 1 + VHOST_CONTROL_COUNT * control_shape_count
        if normalized_limits.request_limit <= minimum_request_count:
            raise ValueError(
                f'virtual-host request limit must be greater than the {minimum_request_count} required context and control requests'
            )
        object.__setattr__(self, 'endpoint', normalized_endpoint)
        object.__setattr__(self, 'scope', normalized_scope)
        object.__setattr__(self, 'candidates', tuple(normalized_candidates))
        object.__setattr__(self, 'limits', normalized_limits)
        object.__setattr__(self, 'insecure', insecure)


@dataclass(frozen=True, slots=True)
class VirtualHostDiscoveryResult:
    context: ProbeObservation
    controls: tuple[ProbeObservation, ...]
    observations: tuple[VirtualHostObservation, ...]
    request_count: int
    attempted_candidate_count: int
    stop_reason: str
    request_error_count: int = 0
    request_error_types: tuple[str, ...] = ()
    scan_error_type: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    hostname: str
    http_host: str
    tls_server_name: str | None
    phase: ProbePhase
    status: int | None = None
    location: str | None = None
    body: bytes = b''
    body_truncated: bool = False
    tls_verified: bool | None = None
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class VirtualHostObservation:
    endpoint: str
    hostname: str
    http_host: str
    tls_server_name: str | None
    classification: VirtualHostClassification
    phase: ProbePhase
    status: int | None
    location: str | None
    body_sha256: str
    body_size: int
    body_truncated: bool
    tls_verified: bool | None
    error_type: str | None
    distinct_signals: tuple[str, ...]
    reflection_normalized: bool
    needs_confirmation: bool
    context_phase: ProbePhase | None
    context_status: int | None
    context_location: str | None
    context_body_sha256: str | None
    context_body_size: int | None
    context_body_truncated: bool | None
    control_phase: ProbePhase | None
    control_status: int | None
    control_location: str | None
    control_body_sha256: str | None
    control_body_size: int | None
    control_body_truncated: bool | None
    confirmation_body_sha256: str | None

    @classmethod
    def from_record(cls, record: Mapping[str, object]) -> Self:
        if record.get('type') != 'vhost':
            raise ValueError('virtual-host record type must be vhost')
        hostname_value = record.get('hostname')
        endpoint_value = record.get('endpoint')
        if not isinstance(hostname_value, str) or not isinstance(endpoint_value, str):
            raise ValueError('virtual-host record must identify an endpoint and hostname')
        hostname = normalize_virtual_host_hostname(hostname_value)
        endpoint = normalize_virtual_host_endpoint(endpoint_value)
        parsed = urlsplit(endpoint)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        expected_http_host = _authority(hostname, parsed.scheme, port)
        expected_tls_server_name = hostname if parsed.scheme == 'https' else None
        if record.get('http_host') != expected_http_host or record.get('tls_server_name') != expected_tls_server_name:
            raise ValueError('virtual-host record must keep HTTP Host and TLS SNI aligned')
        if record.get('classification') != 'distinct':
            raise ValueError('completed virtual-host evidence must be classified distinct')
        phase = record.get('phase')
        if phase != 'body':
            raise ValueError('completed virtual-host evidence must reach the response body')
        status = record.get('status')
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError('virtual-host record has an invalid HTTP status')
        location = record.get('location')
        if location is not None and not isinstance(location, str):
            raise ValueError('virtual-host record has an invalid location')
        body_sha256 = record.get('body_sha256')
        if (
            not isinstance(body_sha256, str)
            or len(body_sha256) != 64
            or any(character not in '0123456789abcdef' for character in body_sha256)
        ):
            raise ValueError('virtual-host record has an invalid body digest')
        body_size = record.get('body_size')
        if isinstance(body_size, bool) or not isinstance(body_size, int) or body_size < 0:
            raise ValueError('virtual-host record has an invalid body size')
        body_truncated = record.get('body_truncated')
        reflection_normalized = record.get('reflection_normalized')
        if not isinstance(body_truncated, bool) or not isinstance(reflection_normalized, bool):
            raise ValueError('virtual-host record has invalid body flags')
        context_phase = record.get('context_phase')
        if context_phase != 'body':
            raise ValueError('virtual-host context evidence must reach the response body')
        context_status = record.get('context_status')
        if isinstance(context_status, bool) or not isinstance(context_status, int) or not 100 <= context_status <= 599:
            raise ValueError('virtual-host record has an invalid context HTTP status')
        context_location = record.get('context_location')
        if context_location is not None and not isinstance(context_location, str):
            raise ValueError('virtual-host record has an invalid context location')
        context_body_sha256 = record.get('context_body_sha256')
        if (
            not isinstance(context_body_sha256, str)
            or len(context_body_sha256) != 64
            or any(character not in '0123456789abcdef' for character in context_body_sha256)
        ):
            raise ValueError('virtual-host record has an invalid context body digest')
        context_body_size = record.get('context_body_size')
        if isinstance(context_body_size, bool) or not isinstance(context_body_size, int) or context_body_size < 0:
            raise ValueError('virtual-host record has an invalid context body size')
        context_body_truncated = record.get('context_body_truncated')
        if not isinstance(context_body_truncated, bool):
            raise ValueError('virtual-host record has an invalid context body flag')
        control_phase = record.get('control_phase')
        if control_phase != 'body':
            raise ValueError('virtual-host control evidence must reach the response body')
        control_status = record.get('control_status')
        if isinstance(control_status, bool) or not isinstance(control_status, int) or not 100 <= control_status <= 599:
            raise ValueError('virtual-host record has an invalid control HTTP status')
        control_location = record.get('control_location')
        if control_location is not None and not isinstance(control_location, str):
            raise ValueError('virtual-host record has an invalid control location')
        control_body_sha256 = record.get('control_body_sha256')
        if (
            not isinstance(control_body_sha256, str)
            or len(control_body_sha256) != 64
            or any(character not in '0123456789abcdef' for character in control_body_sha256)
        ):
            raise ValueError('virtual-host record has an invalid control body digest')
        control_body_size = record.get('control_body_size')
        if isinstance(control_body_size, bool) or not isinstance(control_body_size, int) or control_body_size < 0:
            raise ValueError('virtual-host record has an invalid control body size')
        control_body_truncated = record.get('control_body_truncated')
        if not isinstance(control_body_truncated, bool):
            raise ValueError('virtual-host record has an invalid control body flag')
        tls_verified = record.get('tls_verified')
        if (parsed.scheme == 'https' and not isinstance(tls_verified, bool)) or (
            parsed.scheme == 'http' and tls_verified is not None
        ):
            raise ValueError('virtual-host record has invalid TLS verification evidence')
        if 'error_type' in record:
            raise ValueError('virtual-host records must not serialize transient transport errors')
        confirmation_body_sha256 = record.get('confirmation_body_sha256')
        if confirmation_body_sha256 is not None and (
            not isinstance(confirmation_body_sha256, str)
            or len(confirmation_body_sha256) != 64
            or any(character not in '0123456789abcdef' for character in confirmation_body_sha256)
        ):
            raise ValueError('virtual-host record has an invalid confirmation body digest')
        if confirmation_body_sha256 is not None and confirmation_body_sha256 != body_sha256:
            raise ValueError('virtual-host confirmation must match the candidate body digest')
        signals_value = record.get('distinct_signals')
        if (
            not isinstance(signals_value, list)
            or not signals_value
            or any(not isinstance(signal, str) or signal not in _FINGERPRINT_SIGNALS for signal in signals_value)
            or len(signals_value) != len(set(signals_value))
        ):
            raise ValueError('virtual-host record has invalid distinct signals')
        candidate_fingerprint = _Fingerprint(
            phase='body',
            status=status,
            location=location,
            body_sha256=body_sha256,
            body_size=body_size,
            body_truncated=body_truncated,
            error_type=None,
        )
        context_fingerprint = _Fingerprint(
            phase='body',
            status=context_status,
            location=context_location,
            body_sha256=context_body_sha256,
            body_size=context_body_size,
            body_truncated=context_body_truncated,
            error_type=None,
        )
        control_fingerprint = _Fingerprint(
            phase='body',
            status=control_status,
            location=control_location,
            body_sha256=control_body_sha256,
            body_size=control_body_size,
            body_truncated=control_body_truncated,
            error_type=None,
        )
        confirmation_fingerprint = candidate_fingerprint if confirmation_body_sha256 is not None else None
        classification, actual_signals, needs_confirmation, _confirmation_used = _classify_fingerprints(
            candidate_fingerprint,
            context_fingerprint,
            (control_fingerprint,) * VHOST_CONTROL_COUNT,
            confirmation_fingerprint,
        )
        if classification != 'distinct' or needs_confirmation:
            raise ValueError('virtual-host record does not contain confirmed distinct evidence')
        if tuple(signals_value) != actual_signals:
            raise ValueError('virtual-host record distinct signals do not match baseline evidence')
        return cls(
            endpoint=endpoint,
            hostname=hostname,
            http_host=expected_http_host,
            tls_server_name=expected_tls_server_name,
            classification='distinct',
            phase=cast('ProbePhase', phase),
            status=status,
            location=location,
            body_sha256=body_sha256,
            body_size=body_size,
            body_truncated=body_truncated,
            tls_verified=cast('bool | None', tls_verified),
            error_type=None,
            distinct_signals=tuple(signals_value),
            reflection_normalized=reflection_normalized,
            needs_confirmation=False,
            context_phase='body',
            context_status=context_status,
            context_location=context_location,
            context_body_sha256=context_body_sha256,
            context_body_size=context_body_size,
            context_body_truncated=context_body_truncated,
            control_phase=cast('ProbePhase', control_phase),
            control_status=control_status,
            control_location=control_location,
            control_body_sha256=control_body_sha256,
            control_body_size=control_body_size,
            control_body_truncated=control_body_truncated,
            confirmation_body_sha256=cast('str | None', confirmation_body_sha256),
        )

    def to_record(self) -> dict[str, object]:
        return {
            'type': 'vhost',
            'endpoint': self.endpoint,
            'hostname': self.hostname,
            'http_host': self.http_host,
            'tls_server_name': self.tls_server_name,
            'classification': self.classification,
            'phase': self.phase,
            'status': self.status,
            'location': self.location,
            'body_sha256': self.body_sha256,
            'body_size': self.body_size,
            'body_truncated': self.body_truncated,
            'context_phase': self.context_phase,
            'context_status': self.context_status,
            'context_location': self.context_location,
            'context_body_sha256': self.context_body_sha256,
            'context_body_size': self.context_body_size,
            'context_body_truncated': self.context_body_truncated,
            'control_phase': self.control_phase,
            'control_status': self.control_status,
            'control_location': self.control_location,
            'control_body_sha256': self.control_body_sha256,
            'control_body_size': self.control_body_size,
            'control_body_truncated': self.control_body_truncated,
            'confirmation_body_sha256': self.confirmation_body_sha256,
            'tls_verified': self.tls_verified,
            'distinct_signals': list(self.distinct_signals),
            'reflection_normalized': self.reflection_normalized,
        }

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.endpoint,
            self.hostname,
            self.http_host,
            self.tls_server_name or '',
            self.classification,
            self.phase,
            self.status if self.status is not None else -1,
            self.location or '',
            self.body_sha256,
            self.body_size,
            self.body_truncated,
            self.context_phase or '',
            self.context_status if self.context_status is not None else -1,
            self.context_location or '',
            self.context_body_sha256 or '',
            self.context_body_size if self.context_body_size is not None else -1,
            -1 if self.context_body_truncated is None else int(self.context_body_truncated),
            self.control_phase or '',
            self.control_status if self.control_status is not None else -1,
            self.control_location or '',
            self.control_body_sha256 or '',
            self.control_body_size if self.control_body_size is not None else -1,
            -1 if self.control_body_truncated is None else int(self.control_body_truncated),
            self.confirmation_body_sha256 or '',
            -1 if self.tls_verified is None else int(self.tls_verified),
            self.error_type or '',
            self.distinct_signals,
            self.reflection_normalized,
            self.needs_confirmation,
        )


@dataclass(frozen=True, slots=True)
class HarvestedVirtualHostResult:
    observations: tuple[VirtualHostObservation, ...]
    request_count: int
    endpoint_count: int
    total_endpoint_count: int
    candidate_endpoint_count: int
    total_candidate_endpoint_count: int
    stop_reason: str
    request_error_count: int = 0
    request_error_types: tuple[str, ...] = ()
    scan_error_type: str | None = None


class VirtualHostDiscoveryCancelled(asyncio.CancelledError):
    """Carry completed virtual-host evidence while preserving cancellation."""

    def __init__(self, result: HarvestedVirtualHostResult) -> None:
        super().__init__('virtual-host discovery cancelled')
        self.result = result


@dataclass(frozen=True, slots=True)
class _Fingerprint:
    phase: ProbePhase
    status: int | None
    location: str | None
    body_sha256: str
    body_size: int
    body_truncated: bool
    error_type: str | None


_FINGERPRINT_SIGNALS = ('phase', 'status', 'location', 'body_size', 'body_sha256')
_BODY_SIGNALS = {'body_size', 'body_sha256'}


def _usable_fingerprint(fingerprint: _Fingerprint) -> bool:
    return fingerprint.error_type is None and fingerprint.phase == 'body' and fingerprint.status is not None


def _fingerprint_signals(candidate: _Fingerprint, baseline: _Fingerprint) -> tuple[str, ...]:
    signals = [signal for signal in ('phase', 'status', 'location') if getattr(candidate, signal) != getattr(baseline, signal)]
    if not candidate.body_truncated and not baseline.body_truncated:
        if candidate.body_size != baseline.body_size:
            signals.append('body_size')
        if candidate.body_sha256 != baseline.body_sha256:
            signals.append('body_sha256')
    return tuple(signals)


def _classify_fingerprints(
    candidate: _Fingerprint,
    context: _Fingerprint,
    controls: tuple[_Fingerprint, ...],
    confirmation: _Fingerprint | None = None,
) -> tuple[VirtualHostClassification, tuple[str, ...], bool, bool]:
    if len(controls) < VHOST_CONTROL_COUNT:
        raise ValueError('virtual-host classification requires at least three controls')
    controls_are_stable = len(set(controls)) == 1 and _usable_fingerprint(controls[0])
    if not controls_are_stable or not _usable_fingerprint(context) or not _usable_fingerprint(candidate):
        return 'indeterminate', (), False, False
    control = controls[0]
    matches_control = not candidate.body_truncated and not control.body_truncated and candidate == control
    matches_context = not candidate.body_truncated and not context.body_truncated and candidate == context
    if matches_control or matches_context:
        return 'default', (), False, False
    control_signals = _fingerprint_signals(candidate, control)
    context_signals = _fingerprint_signals(candidate, context)
    distinct_signals = tuple(signal for signal in _FINGERPRINT_SIGNALS if signal in set(control_signals) | set(context_signals))
    if not control_signals or not context_signals:
        return 'indeterminate', distinct_signals, False, False
    needs_confirmation = set(control_signals) <= _BODY_SIGNALS or set(context_signals) <= _BODY_SIGNALS
    if not needs_confirmation:
        return 'distinct', distinct_signals, False, False
    if confirmation is None:
        return 'indeterminate', distinct_signals, True, False
    confirmed = _usable_fingerprint(confirmation) and not confirmation.body_truncated and confirmation == candidate
    return ('distinct' if confirmed else 'indeterminate'), distinct_signals, False, confirmed


def _authority(hostname: str, scheme: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(hostname)
        hostname = f'[{address.compressed}]' if address.version == 6 else address.compressed
    except ValueError:
        pass
    default_port = 443 if scheme == 'https' else 80
    return hostname if port == default_port else f'{hostname}:{port}'


def _tls_verified(scheme: str, insecure: bool) -> bool | None:
    return None if scheme != 'https' else not insecure


async def _probe(
    session: aiohttp.ClientSession,
    request: VirtualHostRequest,
    hostname: str | None,
) -> ProbeObservation:
    parsed = urlsplit(request.endpoint)
    endpoint_hostname = parsed.hostname or ''
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    probe_hostname = hostname or endpoint_hostname
    http_host = _authority(probe_hostname, parsed.scheme, port)
    tls_server_name = hostname if parsed.scheme == 'https' else None
    try:
        async with session.get(
            request.endpoint,
            allow_redirects=False,
            headers={'Host': http_host} if hostname is not None else None,
            server_hostname=tls_server_name,
            ssl=not (request.insecure and parsed.scheme == 'https'),
        ) as response:
            try:
                body = bytearray()
                while len(body) <= VHOST_BODY_LIMIT:
                    chunk = await response.content.read(min(64 * 1024, VHOST_BODY_LIMIT + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
            except (TimeoutError, aiohttp.ClientError) as error:
                return ProbeObservation(
                    hostname=probe_hostname,
                    http_host=http_host,
                    tls_server_name=tls_server_name,
                    phase='headers',
                    status=response.status,
                    location=response.headers.get('Location'),
                    tls_verified=_tls_verified(parsed.scheme, request.insecure),
                    error_type=type(error).__name__,
                )
            body_truncated = len(body) > VHOST_BODY_LIMIT
            return ProbeObservation(
                hostname=probe_hostname,
                http_host=http_host,
                tls_server_name=tls_server_name,
                phase='body',
                status=response.status,
                location=response.headers.get('Location'),
                body=bytes(body[:VHOST_BODY_LIMIT]),
                body_truncated=body_truncated,
                tls_verified=_tls_verified(parsed.scheme, request.insecure),
            )
    except TimeoutError as error:
        return ProbeObservation(
            hostname=probe_hostname,
            http_host=http_host,
            tls_server_name=tls_server_name,
            phase='connect',
            tls_verified=_tls_verified(parsed.scheme, request.insecure),
            error_type=type(error).__name__,
        )
    except aiohttp.ClientError as error:
        phase: ProbePhase = (
            'tls' if 'ssl' in type(error).__name__.lower() or 'certificate' in type(error).__name__.lower() else 'connect'
        )
        return ProbeObservation(
            hostname=probe_hostname,
            http_host=http_host,
            tls_server_name=tls_server_name,
            phase=phase,
            tls_verified=_tls_verified(parsed.scheme, request.insecure),
            error_type=type(error).__name__,
        )


async def _probe_batch(
    session: aiohttp.ClientSession,
    request: VirtualHostRequest,
    hostnames: tuple[str, ...],
    completed: dict[int, ProbeObservation],
) -> None:
    tasks = [asyncio.create_task(_probe(session, request, hostname)) for hostname in hostnames]

    def retain_completed() -> None:
        for index, task in enumerate(tasks):
            if task.done() and not task.cancelled() and task.exception() is None:
                completed[index] = task.result()

    try:
        completed.update(enumerate(await asyncio.gather(*tasks)))
    except (asyncio.CancelledError, Exception):
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        retain_completed()
        raise


def _new_control_names(shape: tuple[int, ...], scope: str, used_names: set[str]) -> tuple[str, ...]:
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    capacity = len(alphabet) ** sum(shape)
    used_for_shape = {name for name in used_names if name.endswith(f'.{scope}') and _candidate_shape(name, scope) == shape}
    control_names: list[str] = []
    start = secrets.randbelow(capacity)
    for offset in range(len(used_for_shape) + VHOST_CONTROL_COUNT):
        value = (start + offset) % capacity
        encoded = ['a'] * sum(shape)
        for index in range(len(encoded) - 1, -1, -1):
            value, remainder = divmod(value, len(alphabet))
            encoded[index] = alphabet[remainder]
        labels: list[str] = []
        label_start = 0
        for length in shape:
            labels.append(''.join(encoded[label_start : label_start + length]))
            label_start += length
        control_name = '.'.join((*labels, scope))
        if control_name not in used_for_shape:
            used_for_shape.add(control_name)
            used_names.add(control_name)
            control_names.append(control_name)
            if len(control_names) == VHOST_CONTROL_COUNT:
                return tuple(control_names)
    raise ValueError('virtual-host candidate shape leaves fewer than three available unknown controls')


def _classify_candidate(
    request: VirtualHostRequest,
    context: ProbeObservation,
    candidate: ProbeObservation,
    controls: tuple[ProbeObservation, ...],
    *,
    confirmation: ProbeObservation | None = None,
) -> VirtualHostObservation:
    observation = classify_virtual_host(
        request.endpoint,
        context,
        candidate,
        controls,
        confirmation=confirmation,
    )
    if candidate.hostname == request.scope:
        return replace(
            observation,
            classification='indeterminate',
            distinct_signals=(),
            needs_confirmation=False,
        )
    return observation


async def discover_virtual_hosts(
    request: VirtualHostRequest,
    *,
    _preserve_partial_on_cancel: bool = False,
) -> VirtualHostDiscoveryResult:
    timeout = aiohttp.ClientTimeout(total=request.limits.timeout_seconds)
    connector = aiohttp.TCPConnector(limit=request.limits.concurrency, force_close=True)
    request_count = 0
    observations: list[VirtualHostObservation] = []
    controls: list[ProbeObservation] = []
    controls_by_shape: dict[tuple[int, ...], tuple[ProbeObservation, ...]] = {}
    context: ProbeObservation | None = None
    attempted_candidate_count = 0
    stop_reason: str | None = None
    request_error_count = 0
    request_error_types: set[str] = set()
    scan_error_type: str | None = None

    def record_request_errors(probes: tuple[ProbeObservation, ...] | list[ProbeObservation]) -> None:
        nonlocal request_error_count
        for probe in probes:
            if probe.error_type is not None:
                request_error_count += 1
                request_error_types.add(probe.error_type)

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            try:
                async with asyncio.timeout(request.limits.runtime_seconds):
                    request_count += 1
                    context = await _probe(session, request, None)
                    assert context is not None
                    record_request_errors((context,))
                    used_names = set(request.candidates)
                    for candidate in request.candidates:
                        shape = _candidate_shape(candidate, request.scope)
                        if shape in controls_by_shape:
                            continue
                        shape_controls: list[ProbeObservation] = []
                        for control_name in _new_control_names(shape, request.scope, used_names):
                            request_count += 1
                            control = await _probe(session, request, control_name)
                            record_request_errors((control,))
                            shape_controls.append(control)
                            controls.append(control)
                        controls_by_shape[shape] = tuple(shape_controls)
                    while attempted_candidate_count < len(request.candidates) and request_count < request.limits.request_limit:
                        remaining_budget = request.limits.request_limit - request_count
                        remaining_candidates = len(request.candidates) - attempted_candidate_count
                        batch_size = min(
                            request.limits.concurrency,
                            remaining_candidates,
                            max(1, remaining_budget // 2),
                        )
                        candidate_names = request.candidates[attempted_candidate_count : attempted_candidate_count + batch_size]
                        request_count += len(candidate_names)
                        completed_candidates: dict[int, ProbeObservation] = {}
                        try:
                            await _probe_batch(session, request, candidate_names, completed_candidates)
                        except (asyncio.CancelledError, Exception):
                            record_request_errors(list(completed_candidates.values()))
                            observations.extend(
                                _classify_candidate(
                                    request,
                                    context,
                                    completed_candidates[index],
                                    controls_by_shape[_candidate_shape(candidate_names[index], request.scope)],
                                )
                                for index in sorted(completed_candidates)
                            )
                            attempted_candidate_count += len(completed_candidates)
                            raise
                        candidate_probes = [completed_candidates[index] for index in range(len(candidate_names))]
                        record_request_errors(candidate_probes)
                        attempted_candidate_count += len(candidate_probes)
                        batch_observations = [
                            _classify_candidate(
                                request,
                                context,
                                candidate,
                                controls_by_shape[_candidate_shape(candidate.hostname, request.scope)],
                            )
                            for candidate in candidate_probes
                        ]
                        observation_offset = len(observations)
                        observations.extend(batch_observations)
                        confirmation_indexes = [
                            index for index, observation in enumerate(batch_observations) if observation.needs_confirmation
                        ][: request.limits.request_limit - request_count]
                        request_count += len(confirmation_indexes)
                        confirmation_names = tuple(candidate_names[index] for index in confirmation_indexes)
                        completed_confirmations: dict[int, ProbeObservation] = {}
                        try:
                            await _probe_batch(session, request, confirmation_names, completed_confirmations)
                        except (asyncio.CancelledError, Exception):
                            record_request_errors(list(completed_confirmations.values()))
                            for confirmation_index, confirmation in completed_confirmations.items():
                                index = confirmation_indexes[confirmation_index]
                                observations[observation_offset + index] = _classify_candidate(
                                    request,
                                    context,
                                    candidate_probes[index],
                                    controls_by_shape[_candidate_shape(candidate_names[index], request.scope)],
                                    confirmation=confirmation,
                                )
                            raise
                        record_request_errors(list(completed_confirmations.values()))
                        for confirmation_index, confirmation in completed_confirmations.items():
                            index = confirmation_indexes[confirmation_index]
                            observations[observation_offset + index] = _classify_candidate(
                                request,
                                context,
                                candidate_probes[index],
                                controls_by_shape[_candidate_shape(candidate_names[index], request.scope)],
                                confirmation=confirmation,
                            )
            except TimeoutError:
                stop_reason = 'runtime-limit'
            except Exception as error:
                scan_error_type = type(error).__name__
    except asyncio.CancelledError:
        if not _preserve_partial_on_cancel:
            raise
        stop_reason = 'runtime-limit'
    except Exception as error:
        scan_error_type = type(error).__name__
    if context is None:
        parsed = urlsplit(request.endpoint)
        endpoint_hostname = parsed.hostname or ''
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        context = ProbeObservation(
            hostname=endpoint_hostname,
            http_host=_authority(endpoint_hostname, parsed.scheme, port),
            tls_server_name=None,
            phase='connect',
            tls_verified=_tls_verified(parsed.scheme, request.insecure),
            error_type=scan_error_type or 'RuntimeLimit',
        )
    if stop_reason is None:
        all_candidates_complete = attempted_candidate_count == len(request.candidates) and not any(
            observation.needs_confirmation for observation in observations
        )
        if scan_error_type is not None:
            stop_reason = 'scan-error'
        elif not all_candidates_complete:
            stop_reason = 'request-limit'
        else:
            stop_reason = 'request-errors' if request_error_count else 'completed'
    return VirtualHostDiscoveryResult(
        context=context,
        controls=tuple(controls),
        observations=tuple(observations),
        request_count=request_count,
        attempted_candidate_count=attempted_candidate_count,
        stop_reason=stop_reason,
        request_error_count=request_error_count,
        request_error_types=tuple(sorted(request_error_types)),
        scan_error_type=scan_error_type,
    )


def _harvested_endpoints(addresses: tuple[str, ...]) -> tuple[str, ...]:
    parsed_addresses = set()
    for value in addresses:
        try:
            parsed_addresses.add(ipaddress.ip_address(value.strip()))
        except ValueError:
            continue
    ordered_addresses = sorted(parsed_addresses, key=lambda address: (address.version, int(address)))
    return tuple(
        f'{scheme}://{f"[{address.compressed}]" if address.version == 6 else address.compressed}:{port}/'
        for scheme, port in (('https', 443), ('http', 80))
        for address in ordered_addresses
    )


def _candidates_for_budget(
    scope: str,
    candidates: tuple[str, ...],
    request_limit: int,
) -> tuple[tuple[str, ...], bool]:
    selected: list[str] = []
    selected_shapes: set[tuple[int, ...]] = set()
    non_apex_counts: dict[tuple[int, ...], int] = {}
    truncated = False
    for candidate in candidates:
        shape = _candidate_shape(candidate, scope)
        shape_count = non_apex_counts.get(shape, 0) + int(candidate != scope)
        shape_total = len(selected_shapes | {shape})
        minimum_requests = 1 + VHOST_CONTROL_COUNT * shape_total + len(selected) + 1
        if 36 ** sum(shape) - shape_count < VHOST_CONTROL_COUNT or minimum_requests > request_limit:
            truncated = True
            continue
        selected.append(candidate)
        selected_shapes.add(shape)
        non_apex_counts[shape] = shape_count
    return tuple(selected), truncated


async def discover_harvested_virtual_hosts(
    *,
    scope: str,
    addresses: tuple[str, ...],
    candidates: tuple[str, ...],
    limits: VirtualHostLimits,
    insecure: bool = False,
    endpoint_override: str = '',
) -> HarvestedVirtualHostResult:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limits.runtime_seconds
    observations: list[VirtualHostObservation] = []
    request_count = 0
    endpoint_count = 0
    candidate_endpoint_count = 0
    child_stop_reasons: list[str] = []
    candidates_were_limited = False
    runtime_limited = False
    request_error_count = 0
    request_error_types: set[str] = set()
    scan_error_type: str | None = None
    normalized_scope = normalize_virtual_host_hostname(scope)
    normalized_candidates = normalize_virtual_host_candidates(normalized_scope, candidates)
    endpoints = (normalize_virtual_host_endpoint(endpoint_override),) if endpoint_override else _harvested_endpoints(addresses)
    total_endpoint_count = len(endpoints)
    total_candidate_endpoint_count = total_endpoint_count * len(normalized_candidates)
    if not normalized_candidates:
        return HarvestedVirtualHostResult((), 0, 0, total_endpoint_count, 0, 0, 'no-candidates')
    if not endpoints:
        return HarvestedVirtualHostResult((), 0, 0, 0, 0, 0, 'no-endpoints')

    def merge_result(result: VirtualHostDiscoveryResult) -> None:
        nonlocal request_count, candidate_endpoint_count, request_error_count, scan_error_type
        request_count += result.request_count
        candidate_endpoint_count += result.attempted_candidate_count
        request_error_count += result.request_error_count
        request_error_types.update(result.request_error_types)
        observations.extend(result.observations)
        child_stop_reasons.append(result.stop_reason)
        scan_error_type = scan_error_type or result.scan_error_type

    def harvested_result(stop_reason: str) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult(
            observations=tuple(observations),
            request_count=request_count,
            endpoint_count=endpoint_count,
            total_endpoint_count=total_endpoint_count,
            candidate_endpoint_count=candidate_endpoint_count,
            total_candidate_endpoint_count=total_candidate_endpoint_count,
            stop_reason=stop_reason,
            request_error_count=request_error_count,
            request_error_types=tuple(sorted(request_error_types)),
            scan_error_type=scan_error_type,
        )

    maximum_endpoint_count = limits.request_limit // (VHOST_BASELINE_REQUEST_COUNT + 1)
    endpoints_were_limited = len(endpoints) > maximum_endpoint_count
    endpoints = endpoints[:maximum_endpoint_count]
    for index, endpoint in enumerate(endpoints):
        endpoints_left = len(endpoints) - index
        remaining_requests = limits.request_limit - request_count
        endpoint_request_limit = remaining_requests // endpoints_left
        endpoint_candidates, were_limited = _candidates_for_budget(
            normalized_scope,
            normalized_candidates,
            endpoint_request_limit,
        )
        candidates_were_limited = candidates_were_limited or were_limited
        if not endpoint_candidates:
            candidates_were_limited = True
            continue
        remaining_runtime = deadline - loop.time()
        if remaining_runtime <= 0:
            runtime_limited = True
            break
        endpoint_runtime = remaining_runtime / endpoints_left
        if endpoints_left == 1:
            endpoint_runtime -= min(0.001, endpoint_runtime / 2)
        endpoint_count += 1
        logger.info(
            'Virtual-host endpoint %d/%d started: candidates=%d; request-limit=%d; runtime=%.2fs',
            endpoint_count,
            len(endpoints),
            len(endpoint_candidates),
            endpoint_request_limit,
            endpoint_runtime,
        )
        task = asyncio.create_task(
            discover_virtual_hosts(
                VirtualHostRequest(
                    endpoint=endpoint,
                    scope=normalized_scope,
                    candidates=endpoint_candidates,
                    limits=replace(
                        limits,
                        request_limit=endpoint_request_limit,
                        runtime_seconds=endpoint_runtime,
                    ),
                    insecure=insecure,
                ),
                _preserve_partial_on_cancel=True,
            )
        )
        try:
            done, _pending = await asyncio.wait((task,), timeout=max(0, deadline - loop.time()))
        except asyncio.CancelledError as error:
            task.cancel()
            outcome = (await asyncio.gather(task, return_exceptions=True))[0]
            if isinstance(outcome, VirtualHostDiscoveryResult):
                merge_result(outcome)
            scan_error_type = 'CancelledError'
            raise VirtualHostDiscoveryCancelled(harvested_result('cancelled')) from error
        if task in done:
            try:
                result = task.result()
            except asyncio.CancelledError as error:
                scan_error_type = 'CancelledError'
                raise VirtualHostDiscoveryCancelled(harvested_result('cancelled')) from error
            except Exception as error:
                scan_error_type = type(error).__name__
                break
        else:
            runtime_limited = True
            task.cancel()
            try:
                result = await task
            except asyncio.CancelledError as error:
                current_task = asyncio.current_task()
                if current_task is not None and current_task.cancelling():
                    scan_error_type = 'CancelledError'
                    raise VirtualHostDiscoveryCancelled(harvested_result('cancelled')) from error
                break
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                scan_error_type = 'CancelledError'
                merge_result(result)
                raise VirtualHostDiscoveryCancelled(harvested_result('cancelled'))
        merge_result(result)
        logger.info(
            'Virtual-host endpoint %d/%d finished: stop=%s; requests=%d; candidates=%d/%d; errors=%d',
            endpoint_count,
            len(endpoints),
            result.stop_reason,
            result.request_count,
            result.attempted_candidate_count,
            len(endpoint_candidates),
            result.request_error_count + int(result.scan_error_type is not None),
        )
        if runtime_limited or result.scan_error_type is not None:
            break

    if runtime_limited or 'runtime-limit' in child_stop_reasons:
        stop_reason = 'runtime-limit'
    elif scan_error_type is not None:
        stop_reason = 'scan-error'
    elif endpoints_were_limited or candidates_were_limited or 'request-limit' in child_stop_reasons:
        stop_reason = 'request-limit'
    elif request_error_count or 'request-errors' in child_stop_reasons:
        stop_reason = 'request-errors'
    else:
        stop_reason = next((reason for reason in child_stop_reasons if reason != 'completed'), 'completed')
    return harvested_result(stop_reason)


def _replace_authority(value: bytes, authority: str) -> tuple[bytes, bool]:
    hostname_character = rb'[A-Za-z0-9._-]'
    pattern = re.compile(
        rb'(?<!' + hostname_character + rb')' + re.escape(authority.encode('ascii')) + rb'(?!' + hostname_character + rb')',
        re.IGNORECASE,
    )
    normalized, replacements = pattern.subn(b'{authority}', value)
    return normalized, replacements > 0


def _normalize(observation: ProbeObservation) -> tuple[_Fingerprint, str | None, bool]:
    normalized_body, body_reflected = _replace_authority(observation.body, observation.http_host)
    normalized_location: str | None = None
    location_reflected = False
    if observation.location is not None:
        location_bytes, location_reflected = _replace_authority(
            observation.location.encode('utf-8'),
            observation.http_host,
        )
        normalized_location = location_bytes.decode('utf-8')
    return (
        _Fingerprint(
            phase=observation.phase,
            status=observation.status,
            location=normalized_location,
            body_sha256=hashlib.sha256(normalized_body).hexdigest(),
            body_size=len(normalized_body),
            body_truncated=observation.body_truncated,
            error_type=observation.error_type,
        ),
        normalized_location,
        body_reflected or location_reflected,
    )


def classify_virtual_host(
    endpoint: str,
    context: ProbeObservation,
    candidate: ProbeObservation,
    controls: tuple[ProbeObservation, ...],
    *,
    confirmation: ProbeObservation | None = None,
) -> VirtualHostObservation:
    context_fingerprint = _normalize(context)[0]
    control_fingerprints = tuple(_normalize(control)[0] for control in controls)
    candidate_fingerprint, normalized_location, reflection_normalized = _normalize(candidate)
    confirmation_fingerprint: _Fingerprint | None = None
    if confirmation is not None:
        if (
            confirmation.hostname != candidate.hostname
            or confirmation.http_host != candidate.http_host
            or confirmation.tls_server_name != candidate.tls_server_name
        ):
            raise ValueError('confirmation must repeat the same virtual-host authority')
        confirmation_fingerprint = _normalize(confirmation)[0]
    classification, distinct_signals, needs_confirmation, confirmation_used = _classify_fingerprints(
        candidate_fingerprint,
        context_fingerprint,
        control_fingerprints,
        confirmation_fingerprint,
    )
    control_fingerprint = control_fingerprints[0] if len(set(control_fingerprints)) == 1 else None
    return VirtualHostObservation(
        endpoint=endpoint,
        hostname=candidate.hostname,
        http_host=candidate.http_host,
        tls_server_name=candidate.tls_server_name,
        classification=classification,
        phase=candidate.phase,
        status=candidate.status,
        location=normalized_location,
        body_sha256=candidate_fingerprint.body_sha256,
        body_size=candidate_fingerprint.body_size,
        body_truncated=candidate.body_truncated,
        tls_verified=candidate.tls_verified,
        error_type=candidate.error_type,
        distinct_signals=distinct_signals,
        reflection_normalized=reflection_normalized,
        needs_confirmation=needs_confirmation,
        context_phase=context_fingerprint.phase,
        context_status=context_fingerprint.status,
        context_location=context_fingerprint.location,
        context_body_sha256=context_fingerprint.body_sha256,
        context_body_size=context_fingerprint.body_size,
        context_body_truncated=context_fingerprint.body_truncated,
        control_phase=control_fingerprint.phase if control_fingerprint is not None else None,
        control_status=control_fingerprint.status if control_fingerprint is not None else None,
        control_location=control_fingerprint.location if control_fingerprint is not None else None,
        control_body_sha256=control_fingerprint.body_sha256 if control_fingerprint is not None else None,
        control_body_size=control_fingerprint.body_size if control_fingerprint is not None else None,
        control_body_truncated=control_fingerprint.body_truncated if control_fingerprint is not None else None,
        confirmation_body_sha256=(
            confirmation_fingerprint.body_sha256 if confirmation_used and confirmation_fingerprint is not None else None
        ),
    )
