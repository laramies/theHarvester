def normalize_hostname(value: object) -> str | None:
    """Return a canonical hostname, or None when the value is unusable."""
    if not isinstance(value, str):
        return None
    hostname = value.strip().lower().rstrip('.')
    if not hostname:
        return None
    return hostname


def normalize_scoped_hostname(value: object, target: str) -> str | None:
    """Return a canonical hostname when value is inside the target boundary."""
    hostname = normalize_hostname(value)
    normalized_target = normalize_hostname(target)
    if hostname is None or normalized_target is None:
        return None
    if hostname == normalized_target or hostname.endswith(f'.{normalized_target}'):
        return hostname
    return None
