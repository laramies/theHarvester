from collections.abc import Iterable
from ipaddress import ip_address


def normalize_resolver_addresses(values: Iterable[str]) -> list[str]:
    """Return distinct canonical resolver IP addresses in operator order."""
    addresses: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = raw_value.strip()
        if not value:
            continue
        try:
            address = str(ip_address(value))
        except ValueError as error:
            raise ValueError(f'Invalid DNS resolver address: {value}') from error
        if address not in seen:
            addresses.append(address)
            seen.add(address)
    if not addresses:
        raise ValueError('Provide at least one DNS resolver IP address')
    return addresses
