from argparse import Namespace

import pytest

from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_LIMIT,
    DEFAULT_SOURCE_WORKERS,
    EnumerationOptions,
)
from theHarvester.lib.source_catalog import selected_action_names


def test_enumeration_options_fill_the_shared_execution_defaults() -> None:
    options = EnumerationOptions.from_namespace(Namespace(domain='example.com', source='crtsh'))

    assert options == EnumerationOptions(domain='example.com', source='crtsh')
    assert options.limit == DEFAULT_RESULT_LIMIT == 500
    assert options.start == 0
    assert options.dns_recursive_query_limit == DEFAULT_DNS_RECURSIVE_QUERY_LIMIT is None
    assert options.dns_recursive_runtime_seconds == DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS is None
    assert options.source_workers == DEFAULT_SOURCE_WORKERS == 3


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
            source_workers=7,
        )
    )

    assert options.limit == 25
    assert options.start == 5
    assert options.proxies is True
    assert options.quiet is True
    assert options.screenshot == '/tmp/managed-screenshots'
    assert options.source_workers == 7


def test_zero_result_limit_means_unlimited() -> None:
    options = EnumerationOptions(domain='example.com', source='crtsh', limit=0)

    assert options.limit is None


def test_negative_result_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match='result limit cannot be negative'):
        EnumerationOptions(domain='example.com', source='crtsh', limit=-1)


def test_routeviews_is_an_explicit_passive_action_independent_of_source_limits() -> None:
    options = EnumerationOptions.from_namespace(Namespace(domain='example.com', source=None, limit=25, routeviews=True))

    assert options.routeviews is True
    assert options.limit == 25
    assert selected_action_names({'routeviews': True, 'limit': 1}) == ('routeviews',)
    assert selected_action_names({'limit': 10_000}) == ()


def test_enumeration_options_preserve_virtual_host_inputs() -> None:
    options = EnumerationOptions.from_namespace(
        Namespace(
            domain='example.com',
            vhost=True,
            vhost_endpoint='https://192.0.2.10/',
            vhost_candidates=['admin.example.com', 'portal.example.com'],
            vhost_request_limit=25,
            vhost_runtime_seconds=10.0,
            vhost_timeout_seconds=2.0,
            vhost_concurrency=3,
            vhost_insecure=True,
        )
    )

    assert options.vhost is True
    assert options.vhost_endpoint == 'https://192.0.2.10/'
    assert options.vhost_candidates == ('admin.example.com', 'portal.example.com')
    assert options.vhost_request_limit == 25
    assert options.vhost_runtime_seconds == 10.0
    assert options.vhost_timeout_seconds == 2.0
    assert options.vhost_concurrency == 3
    assert options.vhost_insecure is True


@pytest.mark.parametrize(
    'selection',
    [
        {'vhost': True},
        {'vhost_endpoint': 'https://192.0.2.10/'},
        {'vhost_candidates': ['admin.example.com']},
    ],
)
def test_virtual_host_inputs_select_the_direct_action(selection: dict[str, object]) -> None:
    assert selected_action_names(selection) == ('vhost',)
