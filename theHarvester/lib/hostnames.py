def normalize_scoped_hostname(value: object, target: str) -> str | None:
    """Return a canonical hostname when value is inside the target boundary."""
    if not isinstance(value, str):
        return None
    hostname = value.strip().lower().rstrip('.')
    normalized_target = target.strip().lower().rstrip('.')
    if hostname == normalized_target or hostname.endswith(f'.{normalized_target}'):
        return hostname
    return None
