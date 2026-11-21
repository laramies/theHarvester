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


def ip_sort_key(value: str) -> tuple[int, int, str]:
    """Return a numeric sort key for an IP address.

    Sorts IPv4 first (version 4), then IPv6 (version 6), ordered by their numeric
    integer representation. Non-IP strings sort last (version 99).
    """
    clean_val = value.strip()
    try:
        ip = ipaddress.ip_address(clean_val)
        return (int(ip.version), int(ip), '')
    except ValueError:
        return (99, 0, clean_val)


def sort_host_ip_row(value: str) -> str:
    """Sort comma-separated IP addresses within a hostname:ip1,ip2 string."""
    if ':' in value:
        subdomain, addrs_part = value.split(':', 1)
        addrs = [a.strip() for a in addrs_part.split(',') if a.strip()]
        if len(addrs) > 1:
            sorted_addrs = sorted(addrs, key=ip_sort_key)
            return f'{subdomain}:{",".join(sorted_addrs)}'
    return value


def host_ip_sort_key(value: str) -> tuple[str, tuple[tuple[int, int, str], ...], str]:
    """Return a sort key for hostname or hostname:ip1,ip2 strings.

    Sorts by hostname first, then numerically by IP address(es) (IPv4 before IPv6),
    and finally by any non-IP address string.
    """
    if ':' in value:
        subdomain, addrs_part = value.split(':', 1)
        addrs = [a.strip() for a in addrs_part.split(',') if a.strip()]
        if addrs:
            sorted_ip_keys = tuple(sorted(ip_sort_key(a) for a in addrs))
            return (subdomain, sorted_ip_keys, '')
        return (subdomain, (), addrs_part)
    return (value, (), '')
