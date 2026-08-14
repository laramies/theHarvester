from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from theHarvester.lib.dns_consensus import DNSQueryBudget, DNSResponse
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

    async def query(self, hostname: str, budget: DNSQueryBudget | None = None) -> DNSResponse:
        if budget is not None and not budget.consume(3):
            return DNSResponse(rcode='ERROR', error='query-limit')
        if hostname in self.current:
            return DNSResponse(ipv4=('192.0.2.10',))
        if hostname in self.aliases:
            return DNSResponse(cnames=(self.aliases[hostname],))
        if hostname in self.nodata:
            return DNSResponse(rcode='NODATA')
        return DNSResponse(rcode='NXDOMAIN')

    async def query_ptr(self, address: str, budget: DNSQueryBudget | None = None) -> tuple[str, ...]:
        if budget is not None and not budget.consume(1):
            return ()
        return ('edge.example.net',) if address == '192.0.2.10' else ()


class BlockingResolver:
    def __init__(self, name: str) -> None:
        self.name = name
        self.cancelled = 0

    async def query(self, _hostname: str, budget: DNSQueryBudget | None = None) -> DNSResponse:
        if budget is not None and not budget.consume(3):
            return DNSResponse(rcode='ERROR', error='query-limit')
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        raise AssertionError('unreachable')

    async def query_ptr(self, _address: str, _budget: DNSQueryBudget | None = None) -> tuple[str, ...]:
        return ()


class CnameHeavyResolver:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, _hostname: str, budget: DNSQueryBudget | None = None) -> DNSResponse:
        assert budget is not None
        if not budget.consume(3) or not budget.consume(3):
            return DNSResponse(rcode='ERROR', error='query-limit')
        return DNSResponse(ipv4=('192.0.2.10',), cnames=('edge.example.com',))

    async def query_ptr(self, _address: str, budget: DNSQueryBudget | None = None) -> tuple[str, ...]:
        assert budget is not None
        return () if not budget.consume(1) else ('edge.example.net',)


@pytest.mark.parametrize('runtime_seconds', [float('nan'), float('inf')])
def test_recursive_dns_limits_require_a_finite_runtime(runtime_seconds: float) -> None:
    with pytest.raises(ValueError, match='runtime'):
        RecursiveDNSLimits(depth=1, query_limit=100, runtime_seconds=runtime_seconds)


@pytest.mark.asyncio
async def test_seed_normalization_stops_at_runtime_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester.lib import recursive_dns

    class GuardedSeeds(list[str]):
        def __init__(self) -> None:
            super().__init__(('api.example.com', 'unused.example.com'))
            self.consumed = 0

        def __iter__(self):
            for value in super().__iter__():
                self.consumed += 1
                if self.consumed > 1:
                    pytest.fail('seeds beyond the runtime limit must remain unconsumed')
                yield value

    seeds = GuardedSeeds()
    times = iter((0.0, 1.0))
    monkeypatch.setattr(recursive_dns, 'time', SimpleNamespace(monotonic=lambda: next(times)))
    resolvers = tuple(FakeResolver(f'resolver-{index}', set()) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        seeds,
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=100, runtime_seconds=0.5),
    )

    assert seeds.consumed == 1
    assert result.query_count == 0
    assert result.stop_reason == 'runtime-limit'


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
    assert result.query_count == 348
    assert result.depth_reached == 2
    assert result.stop_reason == 'depth-limit'


@pytest.mark.asyncio
async def test_recursive_dns_retains_ptrs_as_secondary_evidence() -> None:
    current = {'api.example.com', 'dev.api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=200, runtime_seconds=5),
    )

    assert result.findings[0].ptrs == ('edge.example.net',)
    assert result.classifications[0].ptrs == ('edge.example.net',)
    assert result.query_count == 102


@pytest.mark.asyncio
async def test_recursive_dns_does_not_exceed_query_limit_for_ptrs() -> None:
    current = {'api.example.com', 'dev.api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=99, runtime_seconds=5),
    )

    assert result.findings[0].hostname == 'dev.api.example.com'
    assert result.findings[0].ptrs == ()
    assert result.query_count == 99
    assert result.depth_reached == 1
    assert result.stop_reason == 'query-limit'


@pytest.mark.asyncio
async def test_recursive_dns_counts_cname_hops_before_stopping() -> None:
    resolvers = tuple(CnameHeavyResolver(f'resolver-{index}') for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        ('dev',),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=12, runtime_seconds=5),
    )

    assert result.query_count == 12
    assert result.stop_reason == 'query-limit'


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
    assert result.query_count == 9
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

    assert result.query_count == 36
    assert result.stop_reason == 'runtime-limit'
    assert sum(resolver.cancelled for resolver in resolvers) == 12


@pytest.mark.asyncio
async def test_recursive_dns_keeps_searching_after_three_zero_yield_batches() -> None:
    class GuardedLabels(list[str]):
        def __init__(self) -> None:
            super().__init__([*(f'unused{index}' for index in range(150)), 'late'])
            self.consumed = 0

        def __iter__(self):
            for value in super().__iter__():
                self.consumed += 1
                yield value

    current = {'api.example.com', 'late.api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))
    labels = GuardedLabels()

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        labels,
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=None, runtime_seconds=None),
    )

    assert labels.consumed == 151
    assert [finding.hostname for finding in result.findings] == ['late.api.example.com']
    assert result.query_count > 9_486
    assert result.depth_reached == 1
    assert result.zero_yield_batches == 3
    assert result.stop_reason == 'depth-limit'


@pytest.mark.asyncio
async def test_recursive_dns_does_not_reach_a_depth_without_labels() -> None:
    current = {'api.example.com'}
    resolvers = tuple(FakeResolver(f'resolver-{index}', current) for index in range(3))

    result = await discover_recursive_dns(
        'example.com',
        ('api.example.com',),
        (),
        resolvers,
        RecursiveDNSLimits(depth=1, query_limit=100, runtime_seconds=5),
    )

    assert result.depth_reached == 0
    assert result.stop_reason == 'frontier-exhausted'
