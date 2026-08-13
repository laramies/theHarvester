from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal, cast

from theHarvester.lib.evidence_types import format_utc
from theHarvester.lib.result_values import normalize_asn
from theHarvester.lib.virtual_host import normalize_virtual_host_hostname

ProducerKind = Literal['source', 'action']
SubjectKind = Literal['hostname', 'ip']
MAX_ORGANIZATION_LABEL_LENGTH = 255


def _normalize_name(value: str, label: str, *, max_length: int = 255) -> str:
    if not isinstance(value, str) or not (normalized := value.strip()):
        raise ValueError(f'{label} must not be empty')
    try:
        normalized.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError(f'{label} is invalid') from error
    if len(normalized) > max_length or any(unicodedata.category(character) in {'Cc', 'Cf'} for character in normalized):
        raise ValueError(f'{label} is invalid')
    return normalized


def _normalize_subject(kind: SubjectKind, value: str) -> str:
    if kind == 'hostname':
        return normalize_virtual_host_hostname(value)
    if kind == 'ip':
        if not isinstance(value, str) or '%' in value:
            raise ValueError('ASN attribution IP subject must be a canonical IP address')
        try:
            return str(ip_address(value.strip()))
        except ValueError as error:
            raise ValueError('ASN attribution IP subject must be a canonical IP address') from error
    raise ValueError('ASN attribution subject type must be hostname or ip')


def _normalize_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('ASN attribution collected_at must be timezone-aware')
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class AsnAttributionObservation:
    producer_kind: ProducerKind
    producer: str
    asn: str
    organization_label: str
    subject_kind: SubjectKind
    subject_value: str
    collected_at: datetime

    def __post_init__(self) -> None:
        if self.producer_kind not in {'source', 'action'}:
            raise ValueError('ASN attribution producer kind must be source or action')
        object.__setattr__(self, 'producer', _normalize_name(self.producer, 'ASN attribution producer'))
        object.__setattr__(self, 'asn', normalize_asn(self.asn))
        object.__setattr__(
            self,
            'organization_label',
            _normalize_name(
                self.organization_label,
                'ASN organization label',
                max_length=MAX_ORGANIZATION_LABEL_LENGTH,
            ),
        )
        object.__setattr__(self, 'subject_value', _normalize_subject(self.subject_kind, self.subject_value))
        object.__setattr__(self, 'collected_at', _normalize_time(self.collected_at))

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.asn,
            self.producer_kind,
            self.producer,
            self.organization_label,
            self.subject_kind,
            self.subject_value,
            self.collected_at,
        )

    def detail(self) -> dict[str, object]:
        return {
            'type': 'organization-attribution',
            'producer_kind': self.producer_kind,
            'producer': self.producer,
            'organization_label': self.organization_label,
            'subject': {'type': self.subject_kind, 'value': self.subject_value},
            'collected_at': format_utc(self.collected_at),
        }


def canonical_asn_attributions(
    observations: tuple[AsnAttributionObservation, ...] | list[AsnAttributionObservation],
) -> tuple[AsnAttributionObservation, ...]:
    return tuple(sorted(set(observations), key=AsnAttributionObservation.sort_key))


def asn_attribution_details(observations: tuple[AsnAttributionObservation, ...]) -> list[dict[str, object]]:
    return [observation.detail() for observation in canonical_asn_attributions(observations)]


def parse_asn_attribution_details(asn: str, details: object) -> tuple[AsnAttributionObservation, ...]:
    if not isinstance(details, list) or not details:
        raise ValueError('ASN attribution details must be a non-empty array')
    normalized_asn = normalize_asn(asn)
    observations: list[AsnAttributionObservation] = []
    for detail in details:
        if not isinstance(detail, dict) or set(detail) != {
            'type',
            'producer_kind',
            'producer',
            'organization_label',
            'subject',
            'collected_at',
        }:
            raise ValueError('ASN attribution details must contain canonical observation objects')
        subject = detail.get('subject')
        if (
            detail.get('type') != 'organization-attribution'
            or not isinstance(subject, dict)
            or set(subject)
            != {
                'type',
                'value',
            }
        ):
            raise ValueError('ASN attribution details must contain canonical observation objects')
        collected_at = detail.get('collected_at')
        producer_kind = detail.get('producer_kind')
        producer = detail.get('producer')
        organization_label = detail.get('organization_label')
        subject_kind = subject.get('type')
        subject_value = subject.get('value')
        if (
            producer_kind not in {'source', 'action'}
            or not isinstance(producer, str)
            or not isinstance(organization_label, str)
            or subject_kind not in {'hostname', 'ip'}
            or not isinstance(subject_value, str)
            or not isinstance(collected_at, str)
        ):
            raise ValueError('ASN attribution details must contain canonical observation values')
        try:
            parsed_time = datetime.fromisoformat(collected_at)
        except ValueError as error:
            raise ValueError('ASN attribution collected_at must be a canonical UTC timestamp') from error
        observation = AsnAttributionObservation(
            cast('ProducerKind', producer_kind),
            producer,
            normalized_asn,
            organization_label,
            cast('SubjectKind', subject_kind),
            subject_value,
            parsed_time,
        )
        if detail != observation.detail():
            raise ValueError('ASN attribution details must use canonical structured evidence')
        observations.append(observation)
    return canonical_asn_attributions(observations)
