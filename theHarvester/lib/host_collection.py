from argparse import Namespace


class HostCollectionOptionError(ValueError):
    """Raised when host collection is disabled with a host-dependent option."""


def should_collect_hosts(args: Namespace) -> bool:
    """Return whether hostname artifacts should be collected and processed."""
    return not bool(getattr(args, 'no_hosts', False))


def enabled_host_dependent_options(args: Namespace) -> list[str]:
    """Return host-dependent CLI options enabled in an argument namespace."""
    enabled_options: list[str] = []

    boolean_options = (
        ('shodan', '--shodan'),
        ('dns_lookup', '--dns-lookup'),
        ('dns_brute', '--dns-brute'),
        ('take_over', '--take-over'),
    )
    for attribute, option in boolean_options:
        if bool(getattr(args, attribute, False)):
            enabled_options.append(option)

    dns_resolve = getattr(args, 'dns_resolve', '')
    if dns_resolve is None or bool(dns_resolve):
        enabled_options.append('--dns-resolve')

    if bool(getattr(args, 'screenshot', '')):
        enabled_options.append('--screenshot')

    return enabled_options


def validate_host_collection_options(args: Namespace) -> None:
    """Reject host-dependent options when hostname collection is disabled."""
    if should_collect_hosts(args):
        return

    incompatible_options = enabled_host_dependent_options(args)
    if incompatible_options:
        options = ', '.join(incompatible_options)
        raise HostCollectionOptionError(f'--no-hosts cannot be combined with: {options}')
