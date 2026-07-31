from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from theHarvester.lib.dns_validation import (
    Addressability,
    AioDnsResolverVantage,
    DnsResponse,
    DnsValidator,
)


class RuleVantage:
    def __init__(self, name: str, handler: Callable[[str], DnsResponse]) -> None:
        self.name = name
        self.handler = handler

    async def query(self, hostname: str) -> DnsResponse:
        return self.handler(hostname)


def _vantages(handler: Callable[[str], DnsResponse]) -> tuple[RuleVantage, ...]:
    return tuple(RuleVantage(f'resolver-{suffix}', handler) for suffix in ('a', 'b', 'c'))


@pytest.mark.asyncio
async def test_validator_records_two_of_three_consensus_without_identical_addresses() -> None:
    candidate = 'api.example.com'
    responses = {
        'resolver-a': DnsResponse(
            ipv4=('192.0.2.10',),
            cnames=('Edge.Example.NET.',),
            rcode='noerror',
            ttl=300,
            cname_chain=('Edge.Example.NET.',),
        ),
        'resolver-b': DnsResponse(ipv6=('2001:0db8::10',), ttl=120),
        'resolver-c': DnsResponse(rcode='NXDOMAIN'),
    }
    vantages = tuple(
        RuleVantage(name, lambda hostname, name=name: responses[name] if hostname == candidate else DnsResponse(rcode='NXDOMAIN'))
        for name in responses
    )

    result = await DnsValidator(vantages).validate('run-id', 'example.com', (candidate,))

    assert result.classifications[0].addressability is Addressability.CURRENT
    candidate_observations = [observation for observation in result.observations if not observation.is_wildcard_control]
    assert len(candidate_observations) == 3
    assert candidate_observations[0].candidate == candidate
    assert candidate_observations[0].query_name == candidate
    assert candidate_observations[0].resolver == 'resolver-a'
    assert candidate_observations[0].ipv4 == ('192.0.2.10',)
    assert candidate_observations[0].cnames == ('edge.example.net',)
    assert candidate_observations[0].cname_chain == ('edge.example.net',)
    assert candidate_observations[0].rcode == 'NOERROR'
    assert candidate_observations[0].ttl == 300
    assert candidate_observations[0].queried_at.tzinfo is not None
    assert candidate_observations[0].latency_ms >= 0
    assert candidate_observations[1].ipv6 == ('2001:db8::10',)


@pytest.mark.asyncio
async def test_validator_keeps_resolver_disagreement_secondary() -> None:
    candidate = 'api.example.com'
    responses = iter(
        (
            DnsResponse(ipv4=('192.0.2.10',)),
            DnsResponse(rcode='NXDOMAIN'),
            DnsResponse(rcode='ERROR', error='timeout'),
        )
    )
    vantages = tuple(
        RuleVantage(f'resolver-{suffix}', lambda hostname: next(responses) if hostname == candidate else DnsResponse(rcode='NXDOMAIN'))
        for suffix in ('a', 'b', 'c')
    )

    result = await DnsValidator(vantages).validate('run-id', 'example.com', (candidate,))

    assert result.classifications[0].addressability is Addressability.RESOLVER_DISPUTED


@pytest.mark.asyncio
async def test_validator_records_resolver_error_observation() -> None:
    candidate = 'api.example.com'

    class ErrorVantage:
        name = 'resolver-error'

        async def query(self, _hostname: str) -> DnsResponse:
            raise RuntimeError('resolver unavailable')

    validator = DnsValidator(
        (
            ErrorVantage(),
            RuleVantage('resolver-a', lambda _hostname: DnsResponse(rcode='NXDOMAIN')),
            RuleVantage('resolver-b', lambda _hostname: DnsResponse(rcode='NXDOMAIN')),
        )
    )

    result = await validator.validate('run-id', 'example.com', (candidate,))

    error_observation = next(
        observation
        for observation in result.observations
        if observation.candidate == candidate and observation.resolver == 'resolver-error'
    )
    assert error_observation.rcode == 'ERROR'
    assert error_observation.error == 'RuntimeError: resolver unavailable'
    assert result.classifications[0].addressability is Addressability.NOT_CURRENT


@pytest.mark.asyncio
async def test_validator_times_out_a_stalled_resolver() -> None:
    candidate = 'api.example.com'

    class StalledVantage:
        name = 'resolver-stalled'

        async def query(self, _hostname: str) -> DnsResponse:
            await asyncio.Event().wait()
            raise AssertionError('unreachable')

    validator = DnsValidator(
        (
            StalledVantage(),
            RuleVantage('resolver-a', lambda _hostname: DnsResponse(rcode='NXDOMAIN')),
            RuleVantage('resolver-b', lambda _hostname: DnsResponse(rcode='NXDOMAIN')),
        ),
        timeout_seconds=0.01,
    )

    result = await validator.validate('run-id', 'example.com', (candidate,))

    error_observation = next(
        observation
        for observation in result.observations
        if observation.candidate == candidate and observation.resolver == 'resolver-stalled'
    )
    assert error_observation.error is not None
    assert error_observation.error.startswith('TimeoutError')
    assert result.classifications[0].addressability is Addressability.NOT_CURRENT


@pytest.mark.asyncio
async def test_validator_retains_empty_nonterminal_as_secondary_evidence() -> None:
    result = await DnsValidator(_vantages(lambda _hostname: DnsResponse())).validate(
        'run-id',
        'example.com',
        ('branch.example.com',),
    )

    assert result.classifications[0].addressability is Addressability.NOT_CURRENT


@pytest.mark.asyncio
async def test_validator_never_queries_out_of_scope_candidates() -> None:
    queried: list[str] = []

    def handler(hostname: str) -> DnsResponse:
        queried.append(hostname)
        return DnsResponse(rcode='NXDOMAIN')

    result = await DnsValidator(_vantages(handler)).validate(
        'run-id',
        'example.com',
        ('api.example.com', 'outside.test'),
    )

    assert [classification.candidate for classification in result.classifications] == ['api.example.com']
    assert 'outside.test' not in queried


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('candidate_address', 'deterministic_exact_names', 'expected'),
    [
        ('192.0.2.20', (), Addressability.CURRENT),
        ('192.0.2.10', (), Addressability.WILDCARD_INDISTINGUISHABLE),
        ('192.0.2.10', ('api.example.com',), Addressability.CURRENT),
    ],
)
async def test_validator_compares_stable_wildcard_distribution(
    candidate_address: str,
    deterministic_exact_names: tuple[str, ...],
    expected: Addressability,
) -> None:
    candidate = 'api.example.com'

    def handler(hostname: str) -> DnsResponse:
        return DnsResponse(ipv4=(candidate_address if hostname == candidate else '192.0.2.10',))

    result = await DnsValidator(_vantages(handler)).validate(
        'run-id',
        'example.com',
        (candidate,),
        deterministic_exact_names=deterministic_exact_names,
    )

    assert result.classifications[0].addressability is expected


@pytest.mark.asyncio
async def test_validator_detects_nested_wildcard_distribution() -> None:
    candidate = 'api.stage.example.com'

    def handler(hostname: str) -> DnsResponse:
        if hostname == candidate or hostname.endswith('.stage.example.com'):
            return DnsResponse(ipv4=('192.0.2.20',))
        return DnsResponse(rcode='NXDOMAIN')

    result = await DnsValidator(_vantages(handler)).validate('run-id', 'example.com', (candidate,))

    assert result.classifications[0].addressability is Addressability.WILDCARD_INDISTINGUISHABLE


@pytest.mark.asyncio
async def test_validator_detects_wildcard_cname_distribution() -> None:
    response = DnsResponse(
        cnames=('wildcard.example.net',),
        cname_chain=('wildcard.example.net',),
    )

    result = await DnsValidator(_vantages(lambda _hostname: response)).validate(
        'run-id',
        'example.com',
        ('alias.example.com',),
    )

    assert result.classifications[0].addressability is Addressability.WILDCARD_INDISTINGUISHABLE


@pytest.mark.asyncio
async def test_validator_detects_rotating_a_aaaa_and_cname_wildcards() -> None:
    candidate = 'www.example.com'
    control_responses = (
        DnsResponse(ipv4=('192.0.2.1',)),
        DnsResponse(ipv6=('2001:db8::1',)),
        DnsResponse(cnames=('wildcard.example.net',)),
    )

    class RotatingVantage:
        def __init__(self, name: str) -> None:
            self.name = name
            self.index = 0

        async def query(self, hostname: str) -> DnsResponse:
            if hostname == candidate:
                return DnsResponse(ipv4=('192.0.2.90',))
            response = control_responses[self.index % len(control_responses)]
            self.index += 1
            return response

    result = await DnsValidator(tuple(RotatingVantage(f'resolver-{index}') for index in range(3))).validate(
        'run-id',
        'example.com',
        (candidate,),
    )

    assert result.classifications[0].addressability is Addressability.WILDCARD_INDISTINGUISHABLE
    controls = [observation for observation in result.observations if observation.is_wildcard_control]
    assert {address for observation in controls for address in observation.ipv4} == {'192.0.2.1'}
    assert {address for observation in controls for address in observation.ipv6} == {'2001:db8::1'}
    assert {cname for observation in controls for cname in observation.cnames} == {'wildcard.example.net'}


@pytest.mark.asyncio
async def test_validator_uses_deepest_control_and_never_promotes_probes() -> None:
    candidate = 'api.stage.dev.example.com'

    def handler(hostname: str) -> DnsResponse:
        if hostname == candidate:
            return DnsResponse(ipv4=('192.0.2.20',))
        if hostname.endswith('.stage.dev.example.com'):
            return DnsResponse(rcode='NXDOMAIN')
        return DnsResponse(ipv4=('192.0.2.20',))

    result = await DnsValidator(_vantages(handler)).validate('run-id', 'example.com', (candidate,))

    assert result.classifications[0].addressability is Addressability.CURRENT
    controls = [observation for observation in result.observations if observation.is_wildcard_control]
    assert {observation.wildcard_depth for observation in controls} == {
        'example.com',
        'dev.example.com',
        'stage.dev.example.com',
    }
    assert all(observation.candidate is None for observation in controls)
    assert candidate not in {observation.query_name for observation in controls}


def test_validator_requires_three_distinct_vantages() -> None:
    handler = lambda _hostname: DnsResponse(rcode='NXDOMAIN')

    with pytest.raises(ValueError, match='exactly three distinct'):
        DnsValidator((RuleVantage('same', handler), RuleVantage('same', handler), RuleVantage('other', handler)))


@pytest.mark.asyncio
async def test_validator_propagates_cancellation() -> None:
    class CancelledVantage:
        def __init__(self, name: str) -> None:
            self.name = name

        async def query(self, _hostname: str) -> DnsResponse:
            raise asyncio.CancelledError

    validator = DnsValidator(tuple(CancelledVantage(f'resolver-{index}') for index in range(3)))

    with pytest.raises(asyncio.CancelledError):
        await validator.validate('run-id', 'example.com', ('api.example.com',))


@pytest.mark.asyncio
async def test_aiodns_vantage_follows_cname_chain_and_retains_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.dns_validation as validation_module

    closed: list[bool] = []
    queried: list[tuple[str, str]] = []

    class FakeResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            queried.append((hostname, record_type))
            if record_type == 'A' and hostname == 'alias.example.com':
                return SimpleNamespace(
                    answer=[
                        SimpleNamespace(ttl=90, data=SimpleNamespace(cname='Edge.Example.NET.')),
                        SimpleNamespace(ttl=60, data=SimpleNamespace(cname='Origin.Example.NET.')),
                        SimpleNamespace(ttl=30, data=SimpleNamespace(addr='192.0.2.10')),
                    ]
                )
            raise validation_module.aiodns.error.DNSError(validation_module.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(validation_module.aiodns, 'DNSResolver', FakeResolver)
    vantage = AioDnsResolverVantage('192.0.2.53')

    response = await vantage.query('alias.example.com')
    await vantage.close()

    assert response.ipv4 == ('192.0.2.10',)
    assert response.cnames == ('edge.example.net', 'origin.example.net')
    assert response.cname_chain == ('edge.example.net', 'origin.example.net')
    assert response.ttl == 30
    assert response.rcode == 'NOERROR'
    assert response.error is None
    assert closed == [True]
    assert queried == [
        ('alias.example.com', 'A'),
        ('alias.example.com', 'AAAA'),
        ('alias.example.com', 'CNAME'),
    ]


@pytest.mark.asyncio
async def test_aiodns_vantage_records_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.dns_validation as validation_module

    class FakeResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, _hostname: str, _record_type: str):
            raise validation_module.aiodns.error.DNSError(validation_module.aiodns.error.ARES_ENOTFOUND, 'not found')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(validation_module.aiodns, 'DNSResolver', FakeResolver)

    response = await AioDnsResolverVantage('192.0.2.53').query('missing.example.com')

    assert response.rcode == 'NXDOMAIN'
    assert response.ipv4 == ()
    assert response.ipv6 == ()
    assert response.error is None
