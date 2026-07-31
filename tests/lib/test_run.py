from __future__ import annotations

import asyncio
from dataclasses import replace
from uuid import UUID

import pytest

from theHarvester.lib.dns_validation import Addressability, DnsResponse, DnsValidator
from theHarvester.lib.run import (
    Derivation,
    ScopeClass,
    SourceFinding,
    SourceRateLimitedError,
    SourceStatus,
    execute_run,
    legacy_dns_results,
    legacy_hostnames,
)


class FakePassiveSource:
    name = 'fixture'
    family = 'certificate-transparency'

    async def collect(self, target: str) -> list[SourceFinding]:
        assert target == 'example.com'
        return [
            SourceFinding('WWW.Example.COM.', Derivation.PROVIDER),
            SourceFinding('www.example.com', Derivation.PROVIDER),
            SourceFinding('example.com.evil.test', Derivation.SCOPE_EXTENSION),
            SourceFinding('cdn.vendor.test', Derivation.EXTERNAL_RELATIONSHIP),
        ]


class NoopRunStore:
    async def save(self, _result) -> None:
        return None


@pytest.mark.asyncio
async def test_execute_run_propagates_cancellation() -> None:
    class CancelledSource:
        name = 'cancelled'
        family = 'cancelled'

        async def collect(self, _target: str) -> list[SourceFinding]:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await execute_run('example.com', (CancelledSource(),))


@pytest.mark.asyncio
async def test_execute_run_records_scoped_normalized_evidence_end_to_end() -> None:
    result = await execute_run('Example.COM.', (FakePassiveSource(),))
    next_result = await execute_run('example.com', (FakePassiveSource(),))

    assert UUID(result.run_id)
    assert result.run_id != next_result.run_id
    assert result.target == 'example.com'
    assert len(result.source_executions) == 1
    execution = result.source_executions[0]
    assert execution.status is SourceStatus.SUCCEEDED
    assert execution.duration_ms >= 0
    assert execution.result_count == 4
    assert execution.observation_count == 4
    assert execution.entity_count == 3

    assert [(item.value, item.scope_class) for item in result.observations] == [
        ('www.example.com', ScopeClass.IN_SCOPE),
        ('www.example.com', ScopeClass.IN_SCOPE),
        ('example.com.evil.test', ScopeClass.SCOPE_EXTENSION),
        ('cdn.vendor.test', ScopeClass.EXTERNAL_RELATIONSHIP),
    ]
    assert all(item.target == 'example.com' for item in result.observations)
    assert all(item.source == 'fixture' for item in result.observations)
    assert all(item.source_family == 'certificate-transparency' for item in result.observations)
    assert all(item.collected_at.tzinfo is not None for item in result.observations)
    assert [item.derivation for item in result.observations] == [
        Derivation.PROVIDER,
        Derivation.PROVIDER,
        Derivation.SCOPE_EXTENSION,
        Derivation.EXTERNAL_RELATIONSHIP,
    ]

    merged = {item.value: item for item in result.entities}
    assert len(merged['www.example.com'].observations) == 2
    assert merged['www.example.com'].independent_corroboration_count == 1
    assert merged['www.example.com'].scope_classes == (ScopeClass.IN_SCOPE,)
    assert legacy_hostnames(result) == ['www.example.com']


@pytest.mark.asyncio
async def test_execute_run_does_not_persist_implicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.run as run_module

    def fail_on_stash_access():
        raise AssertionError('execute_run must remain an in-memory operation')

    monkeypatch.setattr(run_module, 'StashManager', fail_on_stash_access, raising=False)

    result = await execute_run('example.com', (FakePassiveSource(),))

    assert result.target == 'example.com'


class OutcomeSource:
    name = 'outcome'
    family = 'fixture-family'

    def __init__(self, outcome: list[SourceFinding] | Exception) -> None:
        self.outcome = outcome

    async def collect(self, _target: str) -> list[SourceFinding]:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    ('outcome', 'expected'),
    [
        ([], SourceStatus.EMPTY),
        (RuntimeError('provider failed'), SourceStatus.FAILED),
    ],
)
@pytest.mark.asyncio
async def test_execute_run_records_non_success_source_outcomes(
    caplog: pytest.LogCaptureFixture,
    outcome: list[SourceFinding] | Exception,
    expected: SourceStatus,
) -> None:
    result = await execute_run('example.com', (OutcomeSource(outcome),))

    assert len(result.source_executions) == 1
    execution = result.source_executions[0]
    assert execution.status is expected
    assert execution.duration_ms >= 0
    assert execution.result_count == 0
    assert execution.observation_count == 0
    assert execution.entity_count == 0
    assert result.observations == ()
    assert result.entities == ()
    if expected is SourceStatus.FAILED:
        assert 'Source outcome failed' in caplog.text


@pytest.mark.asyncio
async def test_execute_run_groups_multiple_sources_under_one_run() -> None:
    class CorroboratingSource:
        name = 'corroborating'
        family = 'passive-dns'

        async def collect(self, _target: str) -> list[SourceFinding]:
            return [SourceFinding('www.example.com'), SourceFinding('example.com'), SourceFinding('')]

    result = await execute_run('example.com', (FakePassiveSource(), CorroboratingSource()))

    assert [execution.source for execution in result.source_executions] == ['fixture', 'corroborating']
    assert {execution.run_id for execution in result.source_executions} == {result.run_id}
    assert {observation.run_id for observation in result.observations} == {result.run_id}
    corroborating_execution = result.source_executions[1]
    assert corroborating_execution.status is SourceStatus.SUCCEEDED
    assert corroborating_execution.result_count == 3
    assert corroborating_execution.observation_count == 2
    merged = {entity.value: entity for entity in result.entities}
    assert merged['www.example.com'].independent_corroboration_count == 2
    assert legacy_hostnames(result) == ['www.example.com']


@pytest.mark.asyncio
async def test_execute_run_classifies_once_and_bridges_current_dns_results() -> None:
    candidate = 'api.example.com'

    class CandidateSource:
        name = 'fixture'
        family = 'fixture'

        async def collect(self, _target: str) -> list[SourceFinding]:
            return [SourceFinding(candidate)]

    class Vantage:
        def __init__(self, name: str, address: str) -> None:
            self.name = name
            self.address = address

        async def query(self, hostname: str) -> DnsResponse:
            return DnsResponse(ipv4=(self.address,)) if hostname == candidate else DnsResponse(rcode='NXDOMAIN')

    validator = DnsValidator(
        (
            Vantage('resolver-a', '192.0.2.10'),
            Vantage('resolver-b', '192.0.2.11'),
            Vantage('resolver-c', '192.0.2.12'),
        )
    )

    result = await execute_run('example.com', (CandidateSource(),), dns_validator=validator)

    assert result.entities[0].addressability is Addressability.CURRENT
    assert legacy_hostnames(result, 'fixture') == [candidate]
    assert legacy_dns_results(result, 'fixture') == (
        ['api.example.com:192.0.2.10,192.0.2.11,192.0.2.12'],
        [candidate],
        ['192.0.2.10', '192.0.2.11', '192.0.2.12'],
    )
    control_names = {observation.query_name for observation in result.dns_validations if observation.is_wildcard_control}
    assert not control_names.intersection(observation.value for observation in result.observations)
    assert not control_names.intersection(entity.value for entity in result.entities)


@pytest.mark.asyncio
async def test_crtsh_bridge_executes_once_and_feeds_legacy_consumers(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    process_calls: list[bool] = []

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            process_calls.append(proxy)

        async def get_hostnames(self) -> list[str]:
            return ['WWW.EXAMPLE.COM.', 'www.example.com', 'example.com.evil.test']

    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, domain: str, items: list[str], result_type: str, source: str) -> None:
            stored.append((domain, tuple(items), result_type, source))

    captured: list[run_module.RunResult] = []

    async def execute_with_temporary_store(target, sources):
        result = await run_module.execute_run(target, sources)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', NoopRunStore)
    monkeypatch.setattr(main_module, 'execute_run', execute_with_temporary_store, raising=True)
    crtsh_spec = main_module.get_source_spec('crtsh')
    monkeypatch.setattr(
        main_module,
        'get_source_spec',
        lambda _name: replace(crtsh_spec, family='catalog-family'),
    )

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=True,
            shodan=False,
            source='crtsh',
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert process_calls == [False]
    assert len(captured) == 1
    assert captured[0].source_executions[0].status is SourceStatus.SUCCEEDED
    assert captured[0].source_executions[0].source == 'crtsh'
    assert {observation.source_family for observation in captured[0].observations} == {'catalog-family'}
    assert legacy_hostnames(captured[0]) == ['www.example.com']
    assert stored == [('example.com', ('www.example.com',), 'host', 'CRTsh')]


@pytest.mark.asyncio
async def test_crtsh_bridge_uses_three_resolvers_without_legacy_requery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    candidate = 'www.example.com'

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return [candidate]

    created: list[str] = []
    closed: list[str] = []

    class FakeVantage:
        def __init__(self, nameserver: str) -> None:
            self.name = nameserver
            created.append(nameserver)

        async def query(self, hostname: str) -> DnsResponse:
            return DnsResponse(ipv4=('192.0.2.10',)) if hostname == candidate else DnsResponse(rcode='NXDOMAIN')

        async def close(self) -> None:
            closed.append(self.name)

    class FailOnLegacyChecker:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError('validated evidence must not be queried again')

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args: object) -> None:
            return None

        async def store(self, *_args: object) -> None:
            return None

    captured: list[run_module.RunResult] = []
    output: list[object] = []

    async def capture_run(target, sources, **kwargs):
        result = await run_module.execute_run(target, sources, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module, 'AioDnsResolverVantage', FakeVantage, raising=False)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FailOnLegacyChecker)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', NoopRunStore)
    monkeypatch.setattr(main_module, 'execute_run', capture_run, raising=True)
    monkeypatch.setattr(main_module.output_logger, 'info', output.append)

    monkeypatch.setattr(
        main_module.sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await main_module.start()

    assert exit_info.value.code == 0
    assert set(created) == {'192.0.2.53', '192.0.2.54', '192.0.2.55'}
    assert set(closed) == set(created)
    assert captured[0].entities[0].addressability is Addressability.CURRENT
    terminal = '\n'.join(map(str, output))
    assert terminal.count(candidate) == 1
    assert 'status=currently-addressable; sources=crtsh' in terminal


@pytest.mark.asyncio
async def test_dnsdb_bridge_preserves_partial_results_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    class FakeDNSDBSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            raise SourceRateLimitedError(
                'DNSDB result limit reached',
                findings=(SourceFinding('partial.example.com'),),
            )

        async def get_hostnames(self) -> list[str]:
            raise AssertionError('partial findings must come from the incomplete source result')

    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, domain: str, items: list[str], result_type: str, source: str) -> None:
            stored.append((domain, tuple(items), result_type, source))

    captured: list[run_module.RunResult] = []

    async def capture_run(target, sources):
        result = await run_module.execute_run(target, sources)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.dnsdb, 'SearchDNSDB', FakeDNSDBSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', NoopRunStore)
    monkeypatch.setattr(main_module, 'execute_run', capture_run, raising=True)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=True,
            shodan=False,
            source='dnsdb',
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert len(captured) == 1
    assert captured[0].source_executions[0].status is SourceStatus.RATE_LIMITED
    assert {observation.value for observation in captured[0].observations} == {'partial.example.com'}
    assert stored == [('example.com', ('partial.example.com',), 'host', 'dnsdb')]
