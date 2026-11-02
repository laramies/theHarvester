import ipaddress


def normalize_hostname(value: str) -> str:
    hostname = value.strip().rstrip('.').lower()
    if not hostname:
        raise ValueError('hostname must not be empty')
    try:
        hostname = hostname.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise ValueError('hostname must be valid') from error
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError('hostname must not be an IP address')
    labels = hostname.split('.')
    if len(hostname) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith('-')
        or label.endswith('-')
        or not all(character.isalnum() or character == '-' for character in label)
        for label in labels
    ):
        raise ValueError('hostname must be valid')
    return hostname


def normalize_scoped_hostname(value: object, target: str) -> str | None:
    """Return a canonical hostname when value is inside the target boundary."""
    if not isinstance(value, str):
        return None
    try:
        hostname = normalize_hostname(value)
        normalized_target = normalize_hostname(target)
    except ValueError:
        return None
    if hostname == normalized_target or hostname.endswith(f'.{normalized_target}'):
        return hostname
    return None


def host_ip_sort_key(value: str) -> tuple[str, int, int, str]:
    """Return a sort key for hostname or hostname:ip strings.

    Sorts by hostname first, then numerically by IP address (IPv4, then IPv6),
    and finally by any non-IP address string.
    """
    if ':' in value:
        subdomain, addr = value.split(':', 1)
        addr_clean = addr.strip()
        try:
            ip = ipaddress.ip_address(addr_clean)
            return (subdomain, int(ip.version), int(ip), '')
        except ValueError:
            return (subdomain, 99, 0, addr_clean)
    return (value, 0, 0, '')
