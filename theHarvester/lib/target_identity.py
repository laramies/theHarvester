from __future__ import annotations

import ipaddress

from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.result_values import normalize_asn, normalize_ip, normalize_prefix


def normalize_target(value: str) -> str:
    """Preserve the target forms currently accepted by run intake."""
    target = value.strip().rstrip('.')
    if target[:2].casefold() == 'as' and target[2:].isascii() and target[2:].isdecimal():
        return normalize_asn(target)
    target = target.lower()
    if not target or len(target) > 253 or any(character in target for character in '/?#@'):
        raise ValueError('Target must be a hostname or IP address')
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            return normalize_hostname(target)
        except ValueError as error:
            raise ValueError('Target must be a valid hostname') from error


def canonical_target(value: object) -> str:
    """Canonicalize persisted target identity without rejecting legacy free text."""
    target = str(value).strip()
    if target[:2].casefold() == 'as' and target[2:].isascii() and target[2:].isdecimal():
        return normalize_asn(target)
    if '/' in target:
        try:
            return normalize_prefix(target)
        except ValueError:
            pass
    try:
        return normalize_ip(target, label='target')
    except ValueError:
        pass
    try:
        hostname = normalize_hostname(target)
    except ValueError:
        return target
    return hostname if '.' in hostname else target
