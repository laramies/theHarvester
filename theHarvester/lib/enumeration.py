from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Self

from theHarvester.lib.recursive_dns import DEFAULT_RECURSIVE_DNS_QUERY_LIMIT

DEFAULT_RESULT_LIMIT = 500
DEFAULT_RESULT_START = 0
DEFAULT_DNS_RECURSIVE_QUERY_LIMIT = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT
DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class EnumerationOptions:
    """Transport-neutral inputs for one finite theHarvester execution."""

    domain: str
    source: str | None = None
    limit: int = DEFAULT_RESULT_LIMIT
    start: int = DEFAULT_RESULT_START
    proxies: bool = False
    shodan: bool = False
    screenshot: str = ''
    dns_server: str | None = None
    take_over: bool = False
    dns_resolve: str | None = ''
    dns_lookup: bool = False
    dns_brute: bool = False
    dns_recursive_depth: int = 0
    dns_recursive_query_limit: int = DEFAULT_DNS_RECURSIVE_QUERY_LIMIT
    dns_recursive_runtime_seconds: float = DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS
    filename: str = ''
    wordlist: str = ''
    api_scan: bool = False
    quiet: bool = False
    verbose: bool = False

    @classmethod
    def from_namespace(cls, value: Any) -> Self:
        return cls(
            domain=value.domain,
            source=getattr(value, 'source', None),
            limit=getattr(value, 'limit', DEFAULT_RESULT_LIMIT),
            start=getattr(value, 'start', DEFAULT_RESULT_START),
            proxies=getattr(value, 'proxies', False),
            shodan=getattr(value, 'shodan', False),
            screenshot=getattr(value, 'screenshot', ''),
            dns_server=getattr(value, 'dns_server', None),
            take_over=getattr(value, 'take_over', False),
            dns_resolve=getattr(value, 'dns_resolve', ''),
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
            quiet=getattr(value, 'quiet', False),
            verbose=getattr(value, 'verbose', False),
        )
