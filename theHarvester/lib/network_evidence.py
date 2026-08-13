from __future__ import annotations

import json
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import TYPE_CHECKING, Literal, cast

from theHarvester.lib.evidence_types import format_utc
from theHarvester.lib.result_values import normalize_asn, normalize_prefix

if TYPE_CHECKING:
    from collections.abc import Iterable

RpkiState = Literal['valid', 'invalid', 'not-found']
MAX_NETWORK_TEXT_LENGTH = 65_536
MAX_NETWORK_OBSERVATIONS_PER_PREFIX = 10_000
MAX_NETWORK_DETAILS_BYTES = 8 * 1024 * 1024


def _normalize_ip(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('peer address must be a non-empty string')
    if '%' in value:
        raise ValueError('peer address must not contain an IPv6 scope identifier')
    try:
        return str(ip_address(value.strip()))
    except ValueError as error:
        raise ValueError('peer address must be a valid IPv4 or IPv6 address') from error


def _normalize_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not (normalized := value.strip()):
        raise ValueError(f'{label} must not be empty')
    try:
        normalized.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError(f'{label} is invalid') from error
    if len(normalized) > 255 or any(unicodedata.category(character) == 'Cc' for character in normalized):
        raise ValueError(f'{label} is invalid')
    return normalized


def _normalize_text(value: str, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f'{label} must be a string')
    normalized = value.strip()
    if not allow_empty and not normalized:
        raise ValueError(f'{label} must not be empty')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError(f'{label} is invalid') from error
    if len(value) > MAX_NETWORK_TEXT_LENGTH or any(unicodedata.category(character) == 'Cc' for character in value):
        raise ValueError(f'{label} is invalid')
    return value


def _normalize_time(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f'{label} must be timezone-aware')
    return value.astimezone(UTC)


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f'{label} must be an ISO-8601 UTC timestamp')
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f'{label} must be an ISO-8601 UTC timestamp') from error
    normalized = _normalize_time(parsed, label)
    if format_utc(normalized) != value:
        raise ValueError(f'{label} must be a canonical ISO-8601 UTC timestamp')
    return normalized


@dataclass(frozen=True, slots=True)
class PrefixOriginObservation:
    action: str
    prefix: str
    origin_asn: str | int
    collected_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, 'action', _normalize_name(self.action, 'network observation action'))
        object.__setattr__(self, 'prefix', normalize_prefix(self.prefix))
        object.__setattr__(self, 'origin_asn', normalize_asn(self.origin_asn))
        object.__setattr__(self, 'collected_at', _normalize_time(self.collected_at, 'collected_at'))

    def to_record(self) -> dict[str, object]:
        return {
            'type': 'observed-origin',
            'action': self.action,
            'prefix': self.prefix,
            'origin_asn': self.origin_asn,
            'collected_at': format_utc(self.collected_at),
        }


@dataclass(frozen=True, slots=True)
class BgpRouteObservation:
    action: str
    prefix: str
    origin_asn: str | int
    collector: str
    peer_asn: str | int
    peer_address: str
    as_path: str
    communities: str
    observed_at: datetime
    collected_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, 'action', _normalize_name(self.action, 'network observation action'))
        object.__setattr__(self, 'prefix', normalize_prefix(self.prefix))
        object.__setattr__(self, 'origin_asn', normalize_asn(self.origin_asn))
        object.__setattr__(self, 'collector', _normalize_name(self.collector, 'collector'))
        object.__setattr__(self, 'peer_asn', normalize_asn(self.peer_asn))
        object.__setattr__(self, 'peer_address', _normalize_ip(self.peer_address))
        object.__setattr__(self, 'as_path', _normalize_text(self.as_path, 'AS path'))
        object.__setattr__(self, 'communities', _normalize_text(self.communities, 'communities', allow_empty=True))
        object.__setattr__(self, 'observed_at', _normalize_time(self.observed_at, 'observed_at'))
        object.__setattr__(self, 'collected_at', _normalize_time(self.collected_at, 'collected_at'))
        if self.observed_at > self.collected_at:
            raise ValueError('observed_at must not be later than collected_at')

    def to_record(self) -> dict[str, object]:
        return {
            'type': 'bgp-route',
            'action': self.action,
            'prefix': self.prefix,
            'origin_asn': self.origin_asn,
            'collector': self.collector,
            'peer_asn': self.peer_asn,
            'peer_address': self.peer_address,
            'as_path': self.as_path,
            'communities': self.communities,
            'observed_at': format_utc(self.observed_at),
            'collected_at': format_utc(self.collected_at),
        }


@dataclass(frozen=True, slots=True)
class RpkiValidationObservation:
    action: str
    prefix: str
    origin_asn: str | int
    state: RpkiState
    observed_at: datetime
    collected_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, 'action', _normalize_name(self.action, 'network observation action'))
        object.__setattr__(self, 'prefix', normalize_prefix(self.prefix))
        object.__setattr__(self, 'origin_asn', normalize_asn(self.origin_asn))
        if not isinstance(self.state, str) or self.state not in {'valid', 'invalid', 'not-found'}:
            raise ValueError('RPKI state must be valid, invalid, or not-found')
        object.__setattr__(self, 'observed_at', _normalize_time(self.observed_at, 'observed_at'))
        object.__setattr__(self, 'collected_at', _normalize_time(self.collected_at, 'collected_at'))
        if self.observed_at > self.collected_at:
            raise ValueError('observed_at must not be later than collected_at')

    def to_record(self) -> dict[str, object]:
        return {
            'type': 'rpki-validation',
            'action': self.action,
            'prefix': self.prefix,
            'origin_asn': self.origin_asn,
            'state': self.state,
            'observed_at': format_utc(self.observed_at),
            'collected_at': format_utc(self.collected_at),
        }


type NetworkObservation = PrefixOriginObservation | BgpRouteObservation | RpkiValidationObservation


class NetworkEvidenceLimitError(ValueError):
    """Raised when one bounded network-evidence envelope is full."""


def _network_observation_detail(observation: NetworkObservation) -> dict[str, object]:
    record = observation.to_record()
    return {key: value for key, value in record.items() if key != 'prefix'}


def _encoded_detail_size(observation: NetworkObservation) -> int:
    try:
        return len(
            json.dumps(_network_observation_detail(observation), ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('network evidence is not serializable') from error


def _rpki_identity(observation: RpkiValidationObservation) -> tuple[object, ...]:
    return observation.action, observation.prefix, observation.origin_asn, observation.state


def _rpki_conflict_identity(observation: RpkiValidationObservation) -> tuple[object, ...]:
    return observation.action, observation.prefix, observation.origin_asn, observation.observed_at


def _network_observation_identity(observation: NetworkObservation) -> tuple[object, ...]:
    if isinstance(observation, PrefixOriginObservation):
        return type(observation), observation.action, observation.prefix, observation.origin_asn
    if isinstance(observation, BgpRouteObservation):
        return (
            type(observation),
            observation.action,
            observation.prefix,
            observation.origin_asn,
            observation.collector,
            observation.peer_asn,
            observation.peer_address,
            observation.as_path,
            observation.communities,
            observation.observed_at,
        )
    return type(observation), *_rpki_identity(observation)


class NetworkEvidenceAccumulator:
    """Incrementally deduplicate network evidence within its persisted envelope."""

    def __init__(
        self,
        *,
        max_observations_per_prefix: int = MAX_NETWORK_OBSERVATIONS_PER_PREFIX,
        max_details_bytes: int = MAX_NETWORK_DETAILS_BYTES,
    ) -> None:
        if not 1 <= max_observations_per_prefix <= MAX_NETWORK_OBSERVATIONS_PER_PREFIX or not (
            2 <= max_details_bytes <= MAX_NETWORK_DETAILS_BYTES
        ):
            raise ValueError('network evidence limits must stay within the persisted envelope')
        self._max_observations_per_prefix = max_observations_per_prefix
        self._max_details_bytes = max_details_bytes
        self._observations: set[NetworkObservation] = set()
        self._observation_identities: set[tuple[object, ...]] = set()
        self._rpki_states: dict[tuple[object, ...], RpkiState] = {}
        self._prefix_counts: Counter[str] = Counter()
        self._prefix_bytes: dict[str, int] = {}

    def add(self, observation: NetworkObservation) -> bool:
        if not isinstance(observation, (PrefixOriginObservation, BgpRouteObservation, RpkiValidationObservation)):
            raise TypeError('network evidence contains an unsupported observation')
        if isinstance(observation, RpkiValidationObservation):
            identity = _rpki_conflict_identity(observation)
            if (existing := self._rpki_states.get(identity)) is not None and existing != observation.state:
                raise ValueError('network evidence contains conflicting RPKI states')
        observation_identity = _network_observation_identity(observation)
        if observation_identity in self._observation_identities:
            if isinstance(observation, RpkiValidationObservation):
                self._rpki_states[identity] = observation.state
            return False

        count = self._prefix_counts[observation.prefix] + 1
        if count > self._max_observations_per_prefix:
            raise NetworkEvidenceLimitError('network evidence contains too many observations for one prefix')
        encoded_size = self._prefix_bytes.get(observation.prefix, 2) + _encoded_detail_size(observation) + bool(count - 1)
        if encoded_size > self._max_details_bytes:
            raise NetworkEvidenceLimitError('network evidence details exceed the serialized size limit')

        self._observations.add(observation)
        self._observation_identities.add(observation_identity)
        self._prefix_counts[observation.prefix] = count
        self._prefix_bytes[observation.prefix] = encoded_size
        if isinstance(observation, RpkiValidationObservation):
            self._rpki_states[identity] = observation.state
        return True

    def observations(self) -> tuple[NetworkObservation, ...]:
        return canonical_network_observations(self._observations)


def network_observation_sort_key(observation: NetworkObservation) -> tuple[object, ...]:
    type_order = {PrefixOriginObservation: 0, BgpRouteObservation: 1, RpkiValidationObservation: 2}
    record = observation.to_record()
    return (
        observation.prefix,
        observation.origin_asn,
        observation.action,
        type_order[type(observation)],
        tuple((key, str(value)) for key, value in sorted(record.items())),
    )


def canonical_network_observations(observations: Iterable[NetworkObservation]) -> tuple[NetworkObservation, ...]:
    deduplicated: dict[tuple[object, ...], NetworkObservation] = {}
    rpki_states: dict[tuple[object, ...], RpkiState] = {}
    for observation in sorted(set(observations), key=network_observation_sort_key):
        if isinstance(observation, RpkiValidationObservation):
            identity = _rpki_conflict_identity(observation)
            if (existing := rpki_states.get(identity)) is not None and existing != observation.state:
                raise ValueError('network evidence contains conflicting RPKI states')
            rpki_states[identity] = observation.state
        deduplicated.setdefault(_network_observation_identity(observation), observation)
    canonical = tuple(sorted(deduplicated.values(), key=network_observation_sort_key))
    counts = Counter(observation.prefix for observation in canonical)
    if any(count > MAX_NETWORK_OBSERVATIONS_PER_PREFIX for count in counts.values()):
        raise ValueError('network evidence contains too many observations for one prefix')
    return canonical


def network_observation_details(observations: Iterable[NetworkObservation]) -> list[dict[str, object]]:
    details: list[dict[str, object]] = []
    encoded_size = 2
    for observation in canonical_network_observations(observations):
        detail = _network_observation_detail(observation)
        encoded_size += _encoded_detail_size(observation) + bool(details)
        if encoded_size > MAX_NETWORK_DETAILS_BYTES:
            raise ValueError('network evidence details exceed the serialized size limit')
        details.append(detail)
    return details


def parse_network_observation_json(prefix: str, payload: str) -> tuple[NetworkObservation, ...]:
    if not isinstance(payload, str) or len(payload) > MAX_NETWORK_DETAILS_BYTES:
        raise ValueError('network evidence details exceed the serialized size limit')
    try:
        encoded = payload.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError('network evidence details are not valid UTF-8') from error
    if len(encoded) > MAX_NETWORK_DETAILS_BYTES:
        raise ValueError('network evidence details exceed the serialized size limit')
    try:
        details = json.loads(payload)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError('network evidence details are not valid JSON') from error
    return parse_network_observation_details(prefix, details)


def parse_network_observation_details(prefix: str, details: object) -> tuple[NetworkObservation, ...]:
    canonical_prefix = normalize_prefix(prefix)
    if canonical_prefix != prefix:
        raise ValueError('network evidence result value must be a canonical prefix')
    if not isinstance(details, list) or not details:
        raise ValueError('network evidence details must be a non-empty array')
    if len(details) > MAX_NETWORK_OBSERVATIONS_PER_PREFIX:
        raise ValueError('network evidence contains too many observations for one prefix')
    observations: list[NetworkObservation] = []
    keys_by_type = {
        'observed-origin': {'type', 'action', 'origin_asn', 'collected_at'},
        'bgp-route': {
            'type',
            'action',
            'origin_asn',
            'collector',
            'peer_asn',
            'peer_address',
            'as_path',
            'communities',
            'observed_at',
            'collected_at',
        },
        'rpki-validation': {'type', 'action', 'origin_asn', 'state', 'observed_at', 'collected_at'},
    }
    for detail in details:
        if not isinstance(detail, dict):
            raise ValueError('network evidence details must contain objects')
        observation_type = detail.get('type')
        if (
            not isinstance(observation_type, str)
            or observation_type not in keys_by_type
            or set(detail) != keys_by_type[observation_type]
        ):
            raise ValueError('network evidence detail has unsupported fields')
        if observation_type == 'observed-origin':
            observation: NetworkObservation = PrefixOriginObservation(
                action=detail['action'],
                prefix=canonical_prefix,
                origin_asn=detail['origin_asn'],
                collected_at=_parse_time(detail['collected_at'], 'collected_at'),
            )
        elif observation_type == 'bgp-route':
            observation = BgpRouteObservation(
                action=detail['action'],
                prefix=canonical_prefix,
                origin_asn=detail['origin_asn'],
                collector=detail['collector'],
                peer_asn=detail['peer_asn'],
                peer_address=detail['peer_address'],
                as_path=detail['as_path'],
                communities=detail['communities'],
                observed_at=_parse_time(detail['observed_at'], 'observed_at'),
                collected_at=_parse_time(detail['collected_at'], 'collected_at'),
            )
        else:
            observation = RpkiValidationObservation(
                action=detail['action'],
                prefix=canonical_prefix,
                origin_asn=detail['origin_asn'],
                state=cast('RpkiState', detail['state']),
                observed_at=_parse_time(detail['observed_at'], 'observed_at'),
                collected_at=_parse_time(detail['collected_at'], 'collected_at'),
            )
        observations.append(observation)
    canonical = canonical_network_observations(observations)
    if details != network_observation_details(canonical):
        raise ValueError('network evidence details must use canonical structured evidence')
    return canonical
