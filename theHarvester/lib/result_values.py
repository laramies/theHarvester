from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from theHarvester.lib.evidence_types import ResultKind

MAX_ASN = 4_294_967_295


def normalize_asn(value: str | int) -> str:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise ValueError('ASN must be an integer or AS-prefixed integer')
    text = str(value).strip()
    if text[:2].casefold() == 'as':
        text = text[2:]
    if not text.isascii() or not text.isdecimal():
        raise ValueError('ASN must be an integer or AS-prefixed integer')
    number = int(text)
    if not 0 <= number <= MAX_ASN:
        raise ValueError(f'ASN must be between 0 and {MAX_ASN}')
    return f'AS{number}'


def normalize_prefix(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('network prefix must be a non-empty string')
    if '%' in value:
        raise ValueError('network prefix must not contain an IPv6 scope identifier')
    try:
        return str(ip_network(value.strip(), strict=False))
    except ValueError as error:
        raise ValueError('network prefix must be valid IPv4 or IPv6 CIDR') from error


def normalize_result_value(kind: ResultKind | str, value: str) -> str:
    normalized = value.strip()
    if kind == 'asn':
        return normalize_asn(normalized)
    if kind == 'prefix':
        return normalize_prefix(normalized)
    if kind == 'shodan-host':
        if '%' in normalized:
            raise ValueError('Shodan host must not contain an IPv6 scope identifier')
        return str(ip_address(normalized))
    return normalized
