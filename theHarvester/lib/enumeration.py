from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Self

from theHarvester.lib.recursive_dns import DEFAULT_RECURSIVE_DNS_QUERY_LIMIT, DEFAULT_RECURSIVE_DNS_RUNTIME_SECONDS
from theHarvester.lib.virtual_host import (
    DEFAULT_VHOST_CONCURRENCY,
    DEFAULT_VHOST_REQUEST_LIMIT,
    DEFAULT_VHOST_RUNTIME_SECONDS,
    DEFAULT_VHOST_TIMEOUT_SECONDS,
)

DEFAULT_RESULT_LIMIT = 500
DEFAULT_RESULT_START = 0
DEFAULT_SOURCE_WORKERS = 3


@dataclass(frozen=True, slots=True)
class EnumerationOptions:
    """Transport-neutral inputs for one finite theHarvester execution."""

    domain: str
    source: str | None = None
    limit: int | None = DEFAULT_RESULT_LIMIT
    start: int = DEFAULT_RESULT_START
    source_workers: int = DEFAULT_SOURCE_WORKERS
    proxies: bool = False
    routeviews: bool = False
    no_hosts: bool = False
    shodan: bool = False
    screenshot: str = ''
    take_over: bool = False
    dns_resolve: str | None = ''
    dns_resolvers: tuple[str, ...] = ()
    dns_resolver_input: str = ''
    dns_lookup: bool = False
    dns_brute: bool = False
    dns_recursive_depth: int = 0
    dns_recursive_query_limit: int | None = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT
    dns_recursive_runtime_seconds: float | None = DEFAULT_RECURSIVE_DNS_RUNTIME_SECONDS
    filename: str = ''
    wordlist: str = ''
    api_scan: bool = False
    vhost: bool = False
    vhost_endpoint: str = ''
    vhost_candidates: tuple[str, ...] = ()
    vhost_request_limit: int = DEFAULT_VHOST_REQUEST_LIMIT
    vhost_runtime_seconds: float = DEFAULT_VHOST_RUNTIME_SECONDS
    vhost_timeout_seconds: float = DEFAULT_VHOST_TIMEOUT_SECONDS
    vhost_concurrency: int = DEFAULT_VHOST_CONCURRENCY
    vhost_insecure: bool = False
    quiet: bool = False
    verbose: bool = False

    def __post_init__(self) -> None:
        if self.limit is not None and self.limit < 0:
            raise ValueError('result limit cannot be negative')
        if self.limit == 0:
            object.__setattr__(self, 'limit', None)

    @classmethod
    def from_namespace(cls, value: Any) -> Self:
        """Copy CLI or REST-like inputs into the shared execution contract.

        Attributes the namespace does not define keep the dataclass defaults, and
        sequence inputs for tuple fields are frozen into tuples. ``domain`` is
        required, so a namespace without it raises ``AttributeError``.
        """

        values: dict[str, Any] = {}
        for field in fields(cls):
            if field.name == 'domain' or hasattr(value, field.name):
                item = getattr(value, field.name)
                values[field.name] = tuple(item) if isinstance(field.default, tuple) else item
        return cls(**values)
