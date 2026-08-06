from __future__ import annotations

import asyncio

import pytest

from theHarvester.lib.dns_consensus import DNSResponse
from theHarvester.lib.recursive_dns import RecursiveDNSLimits, discover_recursive_dns


class FakeResolver:
    def __init__(
        self,
        name: str,
        current: set[str],
        aliases: dict[str, str] | None = None,
        nodata: set[str] | None = None,
    ) -> None:
        self.name = name
        self.current = current
        self.aliases = aliases or {}
        self.nodata = nodata or set()

    async def query(self, hostname: str) -> DNSResponse:
        if hostname in self.current:
            return DNSResponse(ipv4=('192.0.2.10',))
        if hostname in self.aliases:
            return DNSResponse(cnames=(self.aliases[hostname],))
        if hostname in self.nodata:
            return DNSResponse(rcode='NODATA')
        return DNSResponse(rcode='NXDOMAIN')


class BlockingResolver:
    def __init__(self, name: str) -> None:
        self.name = name
        self.cancelled = 0

    async def query(self, _hostname: str) -> DNSResponse:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise


@pytest.mark.asyncio
async def test_recursive_dns_advances_only_current_candidates_breadth_first() -> None:
    current = {'api.example.com', 'dev.api.example.com', 'v2.dev.api.example.com'}
    resolvers = tuple(
        FakeResolver(
            f'resolver-{index}',
            current,
            {'v2.api.example.com': 'missing.vendor.test'},
            {'dev.dev.api.example.com'},
        )
        for index in range(3)
    )

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev', 'v2'),
        resolvers,
        RecursiveDNSLimits(depth=2, query_limit=1_000, runtime_seconds=5),
    )

    assert [(finding.hostname, finding.parent) for finding in result.findings] == [
        ('dev.api.example.com', 'api.example.com'),
        ('v2.dev.api.example.com', 'dev.api.example.com'),
    ]
    assert [
        (classification.hostname, classification.parent, classification.addressability.value)
        for classification in result.classifications
    ] == [
        ('dev.api.example.com', 'api.example.com', 'currently-addressable'),
        ('v2.api.example.com', 'api.example.com', 'not-currently-addressable'),
        ('dev.dev.api.example.com', 'dev.api.example.com', 'not-currently-addressable'),
        ('v2.dev.api.example.com', 'dev.api.example.com', 'currently-addressable'),
    ]
    assert result.classifications[1].records.cnames == ('missing.vendor.test',)
    assert result.query_count == 114
    assert result.depth_reached == 2
    assert result.stop_reason == 'depth-limit'


@pytest.mark.asyncio
async def test_recursive_dns_stops_before_exceeding_query_limit() -> None:
    current = {'api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=11, runtime_seconds=5),
    )

    assert result.findings == ()
    assert result.query_count == 0
    assert result.depth_reached == 0
    assert result.stop_reason == 'query-limit'


@pytest.mark.asyncio
async def test_recursive_dns_runtime_limit_cancels_pending_queries() -> None:
    resolvers = tuple(BlockingResolver(f'resolver-{index}') for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=100, runtime_seconds=0.01),
    )

    assert result.query_count == 12
    assert result.stop_reason == 'runtime-limit'
    assert sum(resolver.cancelled for resolver in resolvers) == 12


@pytest.mark.asyncio
async def test_recursive_dns_stops_after_three_zero_yield_batches() -> None:
    current = {'api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        tuple(f'unused{index}' for index in range(151)),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=10_000, runtime_seconds=5),
    )

    assert result.findings == ()
    assert result.query_count == 3_162
    assert result.depth_reached == 0
    assert result.zero_yield_batches == 3
    assert result.stop_reason == 'zero-yield'
