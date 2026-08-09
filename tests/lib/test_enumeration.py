from argparse import Namespace

from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_LIMIT,
    EnumerationOptions,
)


def test_enumeration_options_fill_the_shared_execution_defaults() -> None:
    options = EnumerationOptions.from_namespace(Namespace(domain='example.com', source='crtsh'))

    assert options == EnumerationOptions(domain='example.com', source='crtsh')
    assert options.limit == DEFAULT_RESULT_LIMIT == 500
    assert options.start == 0
    assert options.dns_recursive_query_limit == DEFAULT_DNS_RECURSIVE_QUERY_LIMIT == 3_000
    assert options.dns_recursive_runtime_seconds == DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS == 60.0


def test_enumeration_options_preserve_explicit_transport_values() -> None:
    options = EnumerationOptions.from_namespace(
        Namespace(
            domain='example.com',
            source='crtsh',
            limit=25,
            start=5,
            proxies=True,
            quiet=True,
            screenshot='/tmp/managed-screenshots',
        )
    )

    assert options.limit == 25
    assert options.start == 5
    assert options.proxies is True
    assert options.quiet is True
    assert options.screenshot == '/tmp/managed-screenshots'
