from __future__ import annotations

from dataclasses import dataclass
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
DEFAULT_DNS_RECURSIVE_QUERY_LIMIT = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT
DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS = DEFAULT_RECURSIVE_DNS_RUNTIME_SECONDS


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
    dns_server: str | None = None
    take_over: bool = False
    dns_resolve: str | None = ''
    dns_resolvers: tuple[str, ...] = ()
    dns_resolver_input: str = ''
    dns_lookup: bool = False
    dns_brute: bool = False
    dns_recursive_depth: int = 0
    dns_recursive_query_limit: int | None = DEFAULT_DNS_RECURSIVE_QUERY_LIMIT
    dns_recursive_runtime_seconds: float | None = DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS
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
        """Copy CLI or REST-like inputs into the shared execution contract."""

        return cls(
            domain=value.domain,
            source=getattr(value, 'source', None),
            limit=getattr(value, 'limit', DEFAULT_RESULT_LIMIT),
            start=getattr(value, 'start', DEFAULT_RESULT_START),
            source_workers=getattr(value, 'source_workers', DEFAULT_SOURCE_WORKERS),
            proxies=getattr(value, 'proxies', False),
            routeviews=getattr(value, 'routeviews', False),
            no_hosts=getattr(value, 'no_hosts', False),
            shodan=getattr(value, 'shodan', False),
            screenshot=getattr(value, 'screenshot', ''),
            dns_server=getattr(value, 'dns_server', None),
            take_over=getattr(value, 'take_over', False),
            dns_resolve=getattr(value, 'dns_resolve', ''),
            dns_resolvers=tuple(getattr(value, 'dns_resolvers', ())),
            dns_resolver_input=getattr(value, 'dns_resolver_input', ''),
            dns_lookup=getattr(value, 'dns_lookup', False),
            dns_brute=getattr(value, 'dns_brute', False),
            dns_recursive_depth=getattr(value, 'dns_recursive_depth', 0),
            dns_recursive_query_limit=getattr(
                value,
                'dns_recursive_query_limit',
                DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
            ),
            dns_recursive_runtime_seconds=getattr(
                value,
                'dns_recursive_runtime_seconds',
                DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
            ),
            filename=getattr(value, 'filename', ''),
            wordlist=getattr(value, 'wordlist', ''),
            api_scan=getattr(value, 'api_scan', False),
            vhost=getattr(value, 'vhost', False),
            vhost_endpoint=getattr(value, 'vhost_endpoint', ''),
            vhost_candidates=tuple(getattr(value, 'vhost_candidates', ())),
            vhost_request_limit=getattr(value, 'vhost_request_limit', DEFAULT_VHOST_REQUEST_LIMIT),
            vhost_runtime_seconds=getattr(value, 'vhost_runtime_seconds', DEFAULT_VHOST_RUNTIME_SECONDS),
            vhost_timeout_seconds=getattr(value, 'vhost_timeout_seconds', DEFAULT_VHOST_TIMEOUT_SECONDS),
            vhost_concurrency=getattr(value, 'vhost_concurrency', DEFAULT_VHOST_CONCURRENCY),
            vhost_insecure=getattr(value, 'vhost_insecure', False),
            quiet=getattr(value, 'quiet', False),
            verbose=getattr(value, 'verbose', False),
        )
