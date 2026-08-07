from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from theHarvester.lib.dns_consensus import (
    Addressability,
    AioDNSResolverVantage,
    DNSResponse,
    validate_dns_candidates,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class RuleResolver:
    def __init__(self, name: str, query: Callable[[str], DNSResponse]) -> None:
        self.name = name
        self._query = query

    async def query(self, hostname: str) -> DNSResponse:
        return self._query(hostname)


@pytest.mark.asyncio
async def test_two_resolver_vantages_establish_current_addressability() -> None:
    candidate = 'api.example.com'
    resolvers = (
        RuleResolver(
            'resolver-a',
            lambda hostname: DNSResponse(ipv4=('192.0.2.10',)) if hostname == candidate else DNSResponse(rcode='NXDOMAIN'),
        ),
        RuleResolver(
            'resolver-b',
            lambda hostname: DNSResponse(ipv6=('2001:db8::10',)) if hostname == candidate else DNSResponse(rcode='NXDOMAIN'),
        ),
        RuleResolver('resolver-c', lambda _hostname: DNSResponse(rcode='NXDOMAIN')),
    )

    (result,) = await validate_dns_candidates('example.com', (candidate,), resolvers)

    assert result.hostname == candidate
    assert result.addressability is Addressability.CURRENT
    assert result.records.ipv4 == ('192.0.2.10',)
    assert result.records.ipv6 == ('2001:db8::10',)
    candidate_evidence = [item for item in result.validations if item.query_name == candidate]
    assert [item.resolver for item in candidate_evidence] == ['resolver-a', 'resolver-b', 'resolver-c']


@pytest.mark.asyncio
async def test_closest_encloser_wildcard_remains_secondary_evidence() -> None:
    candidate = 'api.dev.example.com'

    def nested_wildcard(hostname: str) -> DNSResponse:
        if hostname == candidate or hostname.endswith('.dev.example.com'):
            return DNSResponse(ipv4=('192.0.2.20',))
        return DNSResponse(rcode='NXDOMAIN')

    resolvers = tuple(RuleResolver(f'resolver-{index}', nested_wildcard) for index in range(3))

    (result,) = await validate_dns_candidates('example.com', (candidate,), resolvers)

    assert result.addressability is Addressability.WILDCARD_INDISTINGUISHABLE
    controls = [item for item in result.validations if item.wildcard_depth is not None]
    assert {item.wildcard_depth for item in controls} == {'example.com', 'dev.example.com'}
    assert len(controls) == 18


@pytest.mark.asyncio
async def test_distinct_exact_answer_is_not_confused_with_wildcard_distribution() -> None:
    candidate = 'api.dev.example.com'

    def distinct_exact_answer(hostname: str) -> DNSResponse:
        if hostname == candidate:
            return DNSResponse(ipv4=('192.0.2.10',))
        if hostname.endswith('.dev.example.com'):
            return DNSResponse(ipv4=('192.0.2.99',))
        return DNSResponse(rcode='NXDOMAIN')

    resolvers = tuple(RuleResolver(f'resolver-{index}', distinct_exact_answer) for index in range(3))

    (result,) = await validate_dns_candidates('example.com', (candidate,), resolvers)

    assert result.addressability is Addressability.CURRENT


@pytest.mark.asyncio
async def test_aiodns_vantage_follows_a_bounded_cname_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester.lib import dns_consensus

    aliases = {
        'alias.example.com': 'Edge.Example.COM.',
        'edge.example.com': 'Origin.Example.COM.',
    }
    closed: list[bool] = []

    class FakeDNSResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            if record_type == 'CNAME' and hostname in aliases:
                return SimpleNamespace(answer=[SimpleNamespace(data=SimpleNamespace(cname=aliases[hostname]))])
            if record_type == 'A' and hostname == 'origin.example.com':
                return SimpleNamespace(answer=[SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))])
            raise dns_consensus.aiodns.error.DNSError(dns_consensus.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(dns_consensus.aiodns, 'DNSResolver', FakeDNSResolver)
    resolver = AioDNSResolverVantage('192.0.2.53', 'example.com')

    response = await resolver.query('alias.example.com')
    await resolver.close()

    assert response.ipv4 == ('192.0.2.10',)
    assert response.cnames == ('edge.example.com', 'origin.example.com')
    assert response.error is None
    assert closed == [True]


@pytest.mark.asyncio
async def test_aiodns_vantage_does_not_follow_a_cname_outside_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester.lib import dns_consensus

    queries: list[str] = []

    class FakeDNSResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            queries.append(hostname)
            if record_type == 'CNAME' and hostname == 'alias.example.com':
                return SimpleNamespace(answer=[SimpleNamespace(data=SimpleNamespace(cname='external.example.net.'))])
            raise dns_consensus.aiodns.error.DNSError(dns_consensus.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            pass

    monkeypatch.setattr(dns_consensus.aiodns, 'DNSResolver', FakeDNSResolver)
    resolver = AioDNSResolverVantage('192.0.2.53', 'example.com')

    response = await resolver.query('alias.example.com')

    assert response.cnames == ('external.example.net',)
    assert set(queries) == {'alias.example.com'}


@pytest.mark.asyncio
async def test_empty_target_is_rejected_before_any_dns_query() -> None:
    queries: list[str] = []

    def query(hostname: str) -> DNSResponse:
        queries.append(hostname)
        return DNSResponse(rcode='NXDOMAIN')

    resolvers = tuple(RuleResolver(f'resolver-{index}', query) for index in range(3))

    with pytest.raises(ValueError, match='target must not be empty'):
        await validate_dns_candidates('', ('api.example.com',), resolvers)

    assert queries == []


@pytest.mark.asyncio
async def test_resolver_vantages_must_be_canonically_distinct() -> None:
    resolvers = (
        RuleResolver('2001:db8::1', lambda _hostname: DNSResponse(rcode='NXDOMAIN')),
        RuleResolver('2001:0db8:0:0:0:0:0:1', lambda _hostname: DNSResponse(rcode='NXDOMAIN')),
        RuleResolver('192.0.2.53', lambda _hostname: DNSResponse(rcode='NXDOMAIN')),
    )

    with pytest.raises(ValueError, match='three distinct resolver vantages'):
        await validate_dns_candidates('example.com', ('api.example.com',), resolvers)


@pytest.mark.asyncio
async def test_candidates_are_normalized_scoped_and_deduplicated_before_queries() -> None:
    queries: list[str] = []

    def query(hostname: str) -> DNSResponse:
        queries.append(hostname)
        return DNSResponse(rcode='NXDOMAIN')

    resolvers = tuple(RuleResolver(f'resolver-{index}', query) for index in range(3))

    results = await validate_dns_candidates(
        'Example.COM.',
        ('API.Example.COM.', 'api.example.com', 'outside.example.net'),
        resolvers,
    )

    assert [result.hostname for result in results] == ['api.example.com']
    assert queries.count('api.example.com') == 3


@pytest.mark.asyncio
async def test_dangling_cname_is_not_currently_addressable() -> None:
    candidate = 'alias.example.com'
    resolvers = tuple(
        RuleResolver(
            f'resolver-{index}',
            lambda hostname: (
                DNSResponse(cnames=('missing.vendor.test',)) if hostname == candidate else DNSResponse(rcode='NXDOMAIN')
            ),
        )
        for index in range(3)
    )

    (result,) = await validate_dns_candidates('example.com', (candidate,), resolvers)

    assert result.addressability is Addressability.NOT_CURRENT
    assert result.records.cnames == ('missing.vendor.test',)
