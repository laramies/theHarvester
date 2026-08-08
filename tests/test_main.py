import asyncio
import json
import logging
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.completed_result import CompletedResult, ResultObservation
from theHarvester.lib.dns_consensus import Addressability
from theHarvester.lib.enumeration import EnumerationOptions
from theHarvester.lib.hostchecker import HostDnsRecords
from theHarvester.lib.recursive_dns import RecursiveDNSClassification, RecursiveDNSFinding, RecursiveDNSResult


@pytest.mark.asyncio
async def test_cli_help_explains_proxy_and_direct_action_scope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    help_text = ' '.join(capsys.readouterr().out.split())
    assert exit_info.value.code == 0
    assert 'Use proxies.yaml for supported discovery-source and takeover requests.' in help_text
    assert 'Accepted for compatibility but currently unused; use --dns-resolve to select resolvers.' in help_text
    assert 'Perform PTR lookups across the /24 network containing each discovered IPv4 address.' in help_text
    assert 'Multiple capabilities select the union of matching sources; they do not filter returned fields.' in help_text
    assert 'Check common API paths with GET, HEAD, and OPTIONS.' in help_text
    assert 'Requests follow redirects.' in help_text


@pytest.mark.parametrize('target', ['Example.COM.', 'WWW.Example.COM.'])
def test_normalize_hosts_for_storage_uses_the_parser_scope(target: str) -> None:
    discovered_hosts: set[object] = {
        'API.Example.COM.',
        'example.com',
        'badexample.com',
        'example.com.attacker.test',
        123,
    }

    assert theharvester_main._normalize_hosts_for_storage(discovered_hosts, target) == {'api.example.com'}


@pytest.mark.asyncio
async def test_rapiddns_hostnames_honor_explicit_dns_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    completed: list[CompletedResult] = []
    output_directory = tmp_path / 'reports.v1'
    output_directory.mkdir()
    output_path = output_directory / 'rapiddns'

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com', 'reported.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('reported.example.com', '192.0.2.20')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.20'}

    class FakeCrtsh:
        execution_status = 'partial'
        stop_reason = 'invalid-response'

        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'crt.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']
            self.hosts = hosts
            self.query_error_count = 1
            self.query_error_types = {'TimeoutError'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            if self.hosts == ['crt.example.com']:
                return ['crt.example.com:192.0.2.30'], ['crt.example.com'], ['192.0.2.30']
            assert self.hosts == ['api.example.com']
            return (
                ['api.example.com:192.0.2.10', 'reported.example.com:192.0.2.21'],
                ['api.example.com', 'reported.example.com'],
                ['192.0.2.10', '192.0.2.21'],
            )

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)

    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh,rapiddns',
            '-r',
            '192.0.2.53',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert ('hostname', 'api.example.com') in completed[0].results
    assert ('hostname', 'crt.example.com') in completed[0].results
    assert ('hostname', 'reported.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.10') in completed[0].results
    assert ('ip-address', '192.0.2.20') in completed[0].results
    assert ('ip-address', '192.0.2.21') in completed[0].results
    assert ('ip-address', '192.0.2.30') in completed[0].results
    assert {execution.source for execution in completed[0].source_executions} == {'crtsh', 'rapiddns'}
    crtsh_execution = next(execution for execution in completed[0].source_executions if execution.source == 'crtsh')
    assert crtsh_execution.status == 'partial'
    assert crtsh_execution.stop_reason == 'invalid-response'
    dns_execution = completed[0].active_evidence.executions[0]
    assert dns_execution.action == 'dns-resolve'
    assert dns_execution.status == 'partial'
    assert dns_execution.error_type == 'TimeoutError'
    assert dns_execution.stop_reason == 'query-errors'
    assert {(observation.kind, observation.value) for observation in dns_execution.observations} == {
        ('ip-address', '192.0.2.10'),
        ('ip-address', '192.0.2.21'),
        ('ip-address', '192.0.2.30'),
    }
    assert ('ip-address', '192.0.2.20') not in {
        (observation.kind, observation.value) for observation in dns_execution.observations
    }
    assert completed[0].evidence_dict()['status'] == 'partial'
    assert {(observation.source, observation.kind, observation.value) for observation in completed[0].observations} >= {
        ('crtsh', 'hostname', 'crt.example.com'),
        ('rapiddns', 'hostname', 'api.example.com'),
        ('rapiddns', 'hostname', 'reported.example.com'),
        ('rapiddns', 'ip-address', '192.0.2.20'),
    }
    assert 'reported.example.com:192.0.2.21' in json.loads(output_path.with_suffix('.json').read_text())['hosts']
    assert output_path.with_suffix('.jsonl').is_file()
    xml_pairs = [
        (element.findtext('hostname'), element.findtext('ip'))
        for element in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('host')
    ]
    assert xml_pairs.count(('reported.example.com', '192.0.2.20')) == 1
    assert xml_pairs.count(('reported.example.com', '192.0.2.21')) == 1


@pytest.mark.asyncio
async def test_dns_brute_utility_persists_action_evidence_before_return(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []
    legacy_writes: list[tuple[object, ...]] = []
    resolved = ['api.example.com:192.0.2.10']

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *args: object) -> None:
            legacy_writes.append(args)

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeDnsForce:
        query_error_count = 1
        query_error_types = {'TimeoutError'}

        def __init__(self, domain: str, nameservers: list[str], verbose: bool) -> None:
            assert domain == 'example.com'
            assert nameservers == []
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return resolved, ['API.Example.COM.'], ['192.0.2.10', 'not-an-ip']

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FakeDnsForce)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='', dns_brute=True, quiet=True),
        return_dns_brute_result=True,
    )

    assert response == resolved
    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-brute'
    assert execution.status == 'partial'
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == 'query-errors'
    assert {(observation.kind, observation.value) for observation in execution.observations} == {
        ('hostname', 'api.example.com'),
        ('ip-address', '192.0.2.10'),
    }
    assert legacy_writes == []


@pytest.mark.asyncio
async def test_dns_brute_query_errors_are_partial_even_without_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class EmptyDnsForce:
        query_error_count = 1
        query_error_types = {'TimeoutError'}

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', EmptyDnsForce)

    assert (
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='', dns_brute=True, quiet=True),
            return_dns_brute_result=True,
        )
        == []
    )

    execution = completed[0].active_evidence.executions[0]
    assert execution.status == 'partial'
    assert execution.result_count == 0
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == 'query-errors'


@pytest.mark.asyncio
async def test_dns_brute_keeps_legacy_json_and_xml_while_persisting_canonical_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stored: list[CompletedResult] = []
    output_path = tmp_path / 'dns-brute'

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            stored.append(result)

    class FakeDnsForce:
        query_error_count = 0
        query_error_types: set[str] = set()

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FakeDnsForce)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            source='',
            dns_brute=True,
            filename=str(output_path),
            quiet=True,
        ),
        return_completed_result=True,
    )

    legacy_json = json.loads(output_path.with_suffix('.json').read_text())
    assert legacy_json['hosts'] == ['api.example.com:192.0.2.10']
    assert 'ips' not in legacy_json
    assert response[6] == []
    xml_pairs = [
        (element.findtext('hostname'), element.findtext('ip'))
        for element in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('host')
    ]
    assert xml_pairs == [('api.example.com', '192.0.2.10')]
    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert ('hostname', 'api.example.com') in completed.results
    assert ('ip-address', '192.0.2.10') in completed.results
    assert stored == [completed]


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
@pytest.mark.asyncio
async def test_dns_brute_failure_persists_before_propagation(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FailingDnsForce:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def run(self):
            raise error_type()

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FailingDnsForce)

    with pytest.raises(error_type):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='', dns_brute=True, quiet=True),
            return_dns_brute_result=True,
        )

    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-brute'
    assert execution.status == 'failed'
    assert execution.error_type == error_type.__name__
    assert execution.stop_reason == ('cancelled' if issubclass(error_type, asyncio.CancelledError) else None)


@pytest.mark.asyncio
async def test_dns_resolve_cancellation_closes_workers_and_persists_before_propagation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class CancelledChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self):
            raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.certspottersearch, 'SearchCertspoter', FakeSource)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeSource)
    monkeypatch.setattr(theharvester_main.shodanct, 'SearchShodanCt', FakeSource)
    monkeypatch.setattr(theharvester_main.subdomaincenter, 'SubdomainCenter', FakeSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', CancelledChecker)

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(
            theharvester_main.start(
                EnumerationOptions(
                    domain='example.com',
                    source='certspotter,crtsh,shodanct,subdomaincenter',
                    dns_resolve='192.0.2.53',
                    quiet=True,
                )
            ),
            timeout=1,
        )

    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-resolve'
    assert execution.status == 'failed'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
async def test_source_cancellation_before_dns_resolution_does_not_claim_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class CancelledSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.certspottersearch, 'SearchCertspoter', CancelledSource)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                source='certspotter',
                dns_resolve='192.0.2.53',
                quiet=True,
            )
        )

    assert len(completed) == 1
    assert completed[0].active_evidence.executions == ()
    assert len(completed[0].source_executions) == 1
    source_execution = completed[0].source_executions[0]
    assert source_execution.source == 'certspotter'
    assert source_execution.status == 'failed'
    assert source_execution.error_type == 'CancelledError'
    assert source_execution.stop_reason == 'cancelled'
    assert completed[0].evidence_dict()['status'] == 'failed'


@pytest.mark.asyncio
async def test_dns_resolve_query_errors_are_partial_even_without_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class EmptyChecker:
        query_error_count = 1
        query_error_types = {'TimeoutError'}

        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert hosts == ['api.example.com']

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.certspottersearch, 'SearchCertspoter', FakeSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', EmptyChecker)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            source='certspotter',
            dns_resolve='192.0.2.53',
            quiet=True,
        ),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    execution = completed.active_evidence.executions[0]
    assert execution.action == 'dns-resolve'
    assert execution.status == 'partial'
    assert execution.result_count == 0
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == 'query-errors'


@pytest.mark.asyncio
async def test_requested_dns_resolve_without_inputs_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='', dns_resolve='192.0.2.53', quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert len(completed.active_evidence.executions) == 1
    execution = completed.active_evidence.executions[0]
    assert execution.action == 'dns-resolve'
    assert execution.status == 'skipped'
    assert execution.stop_reason == 'no-input'


@pytest.mark.asyncio
async def test_rest_dns_lookup_runs_before_return_and_retains_action_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeSecurityScorecard:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.com'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    async def fake_reverse(
        iprange: str,
        callback,
        nameservers: list[str] | None = None,
        error_types: set[str] | None = None,
    ) -> None:
        assert iprange == '192.0.2.0/24'
        assert nameservers is None
        callback('PTR.example.com.')

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecard)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', fake_reverse)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='securityscorecard', dns_lookup=True, quiet=True),
        persist_completed_result=True,
    )

    assert len(response) == 9
    assert response[8] == ['ptr.example.com']
    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-lookup'
    assert execution.status == 'completed'
    assert execution.error_type is None
    assert execution.stop_reason is None
    assert execution.observations[0].kind == 'hostname'
    assert execution.observations[0].value == 'ptr.example.com'


@pytest.mark.asyncio
async def test_requested_dns_lookup_without_ip_ranges_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='', dns_lookup=True, quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert len(completed.active_evidence.executions) == 1
    execution = completed.active_evidence.executions[0]
    assert execution.action == 'dns-lookup'
    assert execution.status == 'skipped'
    assert execution.result_count == 0
    assert execution.stop_reason == 'no-input'


@pytest.mark.asyncio
async def test_dns_lookup_cancels_sibling_ranges_and_persists_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []
    sibling_started = asyncio.Event()
    sibling_cancelled = asyncio.Event()

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeSecurityScorecard:
        def __init__(self, _domain: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10', '198.51.100.10'}

    async def fake_reverse(
        iprange: str,
        callback,
        nameservers: list[str] | None = None,
        error_types: set[str] | None = None,
    ) -> None:
        assert nameservers is None
        if iprange == '192.0.2.0/24':
            callback('partial.example.com')
            await sibling_started.wait()
            raise asyncio.CancelledError
        sibling_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            sibling_cancelled.set()
            raise

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecard)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', fake_reverse)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='securityscorecard', dns_lookup=True, quiet=True),
            persist_completed_result=True,
        )

    assert sibling_cancelled.is_set()
    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-lookup'
    assert execution.status == 'partial'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert [(observation.kind, observation.value) for observation in execution.observations] == [
        ('hostname', 'partial.example.com')
    ]


@pytest.mark.asyncio
async def test_source_failure_retains_normalized_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class PartiallyFailingBuiltWith:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return ['API.Example.COM.', 'api.example.com', 'outside.test']

        async def get_interesting_urls(self) -> set[str]:
            raise RuntimeError('provider page failed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.builtwith, 'SearchBuiltWith', PartiallyFailingBuiltWith)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'builtwith'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert len(completed) == 1
    execution = completed[0].source_executions[0]
    assert execution.status == 'partial'
    assert execution.result_count == 1
    assert execution.error_type == 'RuntimeError'
    assert completed[0].observations == (ResultObservation('builtwith', 'hostname', 'api.example.com'),)


@pytest.mark.asyncio
async def test_source_checkpoint_excludes_other_source_work_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    builtwith_collected = asyncio.Event()
    release_builtwith = asyncio.Event()
    checkpoints: list[CompletedResult] = []
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class PausedBuiltWith:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            builtwith_collected.set()
            return {'early.example.com'}

        async def get_interesting_urls(self) -> set[str]:
            await release_builtwith.wait()
            return set()

        async def get_frameworks(self) -> set[str]:
            return set()

        async def get_languages(self) -> set[str]:
            return set()

        async def get_servers(self) -> set[str]:
            return set()

        async def get_cms(self) -> set[str]:
            return set()

        async def get_analytics(self) -> set[str]:
            return set()

    class FastCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            await builtwith_collected.wait()

        async def get_hostnames(self) -> set[str]:
            return {'committed.example.com'}

    async def capture_checkpoint(result: CompletedResult) -> None:
        checkpoints.append(result)
        if {execution.source for execution in result.source_executions} == {'crtsh'}:
            release_builtwith.set()

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.builtwith, 'SearchBuiltWith', PausedBuiltWith)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FastCrtsh)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'builtwith,crtsh'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start(completed_result_checkpoint=capture_checkpoint)

    assert exit_info.value.code == 0
    crtsh_checkpoint = next(
        result for result in checkpoints if {execution.source for execution in result.source_executions} == {'crtsh'}
    )
    assert ('hostname', 'committed.example.com') in crtsh_checkpoint.results
    assert ('hostname', 'early.example.com') not in crtsh_checkpoint.results
    assert {value for kind, value in completed[0].results if kind == 'hostname'} == {
        'committed.example.com',
        'early.example.com',
    }


@pytest.mark.asyncio
async def test_invalid_source_outcome_is_not_recorded_as_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class InvalidOutcomeCrtsh:
        execution_status = 'typo'

        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', InvalidOutcomeCrtsh)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'crtsh'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed[0].source_executions[0].status == 'failed'
    assert completed[0].source_executions[0].error_type == 'ValueError'


@pytest.mark.asyncio
async def test_recursive_dns_requires_canonically_distinct_resolvers(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '2001:db8::1,2001:0db8:0:0:0:0:0:1,192.0.2.53',
            '--dns-recursive-depth',
            '1',
        ],
    )

    with pytest.raises(ValueError, match='exactly three resolver vantages'):
        await theharvester_main.start()


@pytest.mark.asyncio
async def test_cli_rejects_resolver_file_with_non_ip_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

    resolvers = tmp_path / 'resolvers.txt'
    resolvers.write_text('192.0.2.53\nnot-an-ip\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)

    with pytest.raises(ValueError, match='Invalid DNS resolver address: not-an-ip'):
        await theharvester_main.start(EnumerationOptions(domain='example.com', dns_resolve=str(resolvers), quiet=True))


@pytest.mark.asyncio
async def test_dns_brute_resolver_configuration_does_not_enable_dns_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeDnsForce:
        def __init__(self, domain: str, nameservers: list[str], verbose: bool) -> None:
            assert domain == 'www.example.com'
            assert nameservers == ['192.0.2.53']
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['dev.www.example.com:192.0.2.10'],
                ['dev.www.example.com'],
                ['192.0.2.10'],
            )

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FakeDnsForce)

    result = await theharvester_main.start(
        EnumerationOptions(
            domain='www.example.com',
            source='',
            dns_brute=True,
            dns_resolvers=('192.0.2.53',),
            quiet=True,
        ),
        return_completed_result=True,
    )

    completed = result[-1]
    actions = {execution.action for execution in completed.active_evidence.executions}
    assert 'dns-brute' in actions
    assert 'dns-resolve' not in actions


@pytest.mark.asyncio
async def test_dns_proven_cname_hosts_reach_screenshot_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    visited: set[str] = set()

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert set(hosts) == {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['address.example.com:192.0.2.1', 'alias.example.com'],
                ['address.example.com', 'alias.example.com'],
                ['192.0.2.1'],
            )

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            visited.add(host)
            return host, 'https'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> tuple[str, str]:
            return host, f'{host}.png'

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53',
            '--screenshot',
            str(tmp_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert visited == {'address.example.com', 'alias.example.com'}


class _NoopResultStore:
    async def initialize(self) -> None:
        return None

    async def record_observations(self, *_args: object) -> None:
        return None

    async def save_run(self, _result: CompletedResult) -> None:
        return None


class _ApiHostSource:
    def __init__(self, _word: str) -> None:
        pass

    async def process(self, _proxy: bool) -> None:
        return None

    async def get_hostnames(self) -> set[str]:
        return {'api.example.com'}


class _ApiHostChecker:
    def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
        pass

    async def check(self) -> tuple[list[str], list[str], list[str]]:
        return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']


def _recording_result_store(saved: list[CompletedResult]) -> type[_NoopResultStore]:
    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved.append(result)

    return RecordingResultStore


@pytest.mark.asyncio
async def test_cli_can_capture_an_explicit_target_without_discovery_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            return host, 'https'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> str:
            captured.append(host)
            return host

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'api.example.com', '--screenshot', str(tmp_path), '--quiet'],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured == ['api.example.com']


@pytest.mark.asyncio
async def test_direct_action_evidence_reaches_completed_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, proxy: bool) -> None:
            assert proxy is True
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    class FakeTakeOver:
        def __init__(self, hosts: list[str]) -> None:
            assert hosts == ['api.example.com']
            self.request_count = 2
            self.request_error_count = 0
            self.request_error_types: set[str] = set()
            self.scan_error_type = None

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is True

        async def get_takeover_results(self) -> dict[str, list[dict[str, str]]]:
            return {'https://api.example.com': [{'No such app': 'Heroku'}]}

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            return host, 'reachable'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> str:
            return host

    class FakeShodan:
        error_type = None

        async def search_ip(self, ip: str) -> dict[str, dict[str, list[int]]]:
            return {ip: {'ports': [443]}}

    class FakeApiScanner:
        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')
            self.scan_error_type = None
            self.request_error_count = 0
            self.request_error_types: set[str] = set()

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> set[str]:
            return {'https://example.com/api/v1'}

        def get_interesting_endpoints(self) -> set[str]:
            return {'https://example.com/api/v1'}

        def get_auth_required(self) -> set[str]:
            return set()

        def get_api_versions(self) -> set[str]:
            return {'v1'}

        def get_rate_limits(self) -> dict:
            return {}

        def get_methods(self) -> set[str]:
            return {'GET'}

        def get_status_codes(self) -> set[int]:
            return {200}

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    async def no_sleep(_seconds: float) -> None:
        return None

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api/v1\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(
            api_scan=True,
            dns_resolve='192.0.2.53',
            domain='example.com',
            proxies=True,
            quiet=True,
            screenshot=str(tmp_path),
            shodan=True,
            source='crtsh',
            take_over=True,
            wordlist=str(wordlist),
        ),
        include_breaches=True,
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    assert ('api-endpoint', 'https://example.com/api/v1') in completed.results
    assert ('screenshot', 'api.example.com') in completed.results
    assert ('shodan', '{"ip":"192.0.2.10","result":{"ports":[443]}}') in completed.results
    takeover_result = (
        'takeover',
        '{"matches":[{"No such app":"Heroku"}],"url":"https://api.example.com"}',
    )
    assert takeover_result in completed.results
    takeover_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'takeover')
    assert takeover_execution.status == 'completed'
    assert takeover_execution.result_count == 1
    assert takeover_execution.error_type is None
    assert takeover_execution.stop_reason is None
    shodan_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'shodan')
    assert shodan_execution.status == 'completed'
    assert shodan_execution.result_count == 1
    assert shodan_execution.error_type is None
    assert shodan_execution.stop_reason is None
    api_executions = [execution for execution in completed.active_evidence.executions if execution.action == 'api-scan']
    assert len(api_executions) == 1
    api_execution = api_executions[0]
    assert api_execution.status == 'completed'
    assert api_execution.result_count == 3
    assert api_execution.error_type is None
    assert api_execution.stop_reason is None
    assert {(observation.kind, observation.value) for observation in api_execution.observations} == {
        ('api-endpoint', 'https://example.com/api/v1'),
        ('interesting-url', 'https://example.com/api/v1'),
        ('url', 'https://example.com/api/v1'),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('request_count', 'request_errors', 'scan_error', 'expected_status', 'expected_error', 'expected_reason'),
    [
        (2, 1, None, 'partial', 'TransportError', 'request-errors'),
        (2, 2, None, 'failed', 'TransportError', 'request-errors'),
        (0, 0, 'RuntimeError', 'failed', 'RuntimeError', 'scan-error'),
    ],
)
async def test_takeover_action_records_suppressed_outcome(
    monkeypatch: pytest.MonkeyPatch,
    request_count: int,
    request_errors: int,
    scan_error: str | None,
    expected_status: str,
    expected_error: str,
    expected_reason: str,
) -> None:
    class FakeTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            self.request_count = request_count
            self.request_error_count = request_errors
            self.request_error_types = {'TransportError'} if request_errors else set()
            self.scan_error_type = scan_error

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            return None

        async def get_takeover_results(self) -> dict:
            return {}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FakeTakeOver)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, source='crtsh', take_over=True),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'takeover')
    assert execution.status == expected_status
    assert execution.result_count == 0
    assert execution.error_type == expected_error
    assert execution.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_shodan_action_records_all_target_errors_as_failed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    class FailedShodan:
        error_type = None

        async def search_ip(self, ip: str) -> dict[str, str]:
            raise RuntimeError(f'provider-secret-payload for {ip}')

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FailedShodan)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(
            dns_resolve='192.0.2.53',
            domain='example.com',
            quiet=True,
            shodan=True,
            source='crtsh',
        ),
        return_completed_result=True,
    )

    completed = result[-1]
    shodan_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'shodan')
    assert shodan_execution.status == 'failed'
    assert shodan_execution.result_count == 0
    assert shodan_execution.error_type == 'RuntimeError'
    assert shodan_execution.stop_reason == 'target-errors'
    assert 'provider-secret-payload' not in caplog.text


@pytest.mark.asyncio
async def test_shodan_no_data_is_a_completed_zero_yield_action(monkeypatch: pytest.MonkeyPatch) -> None:
    class EmptyShodan:
        error_type = None

        async def search_ip(self, _ip: str) -> dict:
            return {}

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', EmptyShodan)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(dns_resolve='192.0.2.53', domain='example.com', quiet=True, shodan=True, source='crtsh'),
        return_completed_result=True,
    )

    completed = result[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'shodan')
    assert execution.status == 'completed'
    assert execution.result_count == 0
    assert execution.error_type is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('scan_error', 'request_errors', 'rate_limited', 'expected_status', 'expected_error', 'expected_reason'),
    [
        ('RuntimeError', 0, False, 'failed', 'RuntimeError', 'scan-error'),
        (None, 3, False, 'partial', 'TransportError', 'request-errors'),
        (None, 0, True, 'rate-limited', None, 'rate-limited'),
    ],
)
async def test_api_scan_records_suppressed_scan_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scan_error: str | None,
    request_errors: int,
    rate_limited: bool,
    expected_status: str,
    expected_error: str | None,
    expected_reason: str,
) -> None:
    class FailedApiScanner:
        scan_error_type = scan_error
        request_error_count = request_errors
        request_error_types = {'TransportError'} if request_errors else set()

        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> dict:
            return {}

        def get_interesting_endpoints(self) -> dict:
            return {}

        def get_auth_required(self) -> dict:
            return {}

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict:
            if rate_limited:
                return {'/api': type('RateLimitInfo', (), {'method': 'GET'})()}
            return {}

        def get_methods(self) -> set[str]:
            return set()

        def get_status_codes(self) -> set[int]:
            return set()

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FailedApiScanner)

    result = await theharvester_main.start(
        EnumerationOptions(
            api_scan=True,
            domain='example.com',
            quiet=True,
            wordlist=str(wordlist),
        ),
        return_completed_result=True,
    )

    completed = result[-1]
    api_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'api-scan')
    assert api_execution.status == expected_status
    assert api_execution.result_count == 0
    assert api_execution.error_type == expected_error
    assert api_execution.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_takeover_without_hosts_is_skipped_without_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnexpectedTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            raise AssertionError('takeover should not start without hosts')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', UnexpectedTakeOver)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, take_over=True),
        return_completed_result=True,
    )

    completed = result[-1]
    takeover_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'takeover')
    assert takeover_execution.status == 'skipped'
    assert takeover_execution.result_count == 0
    assert takeover_execution.stop_reason == 'no-input'


@pytest.mark.asyncio
async def test_shodan_without_ips_is_skipped_without_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnexpectedShodan:
        def __init__(self) -> None:
            raise AssertionError('Shodan should not start without IP addresses')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', UnexpectedShodan)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, shodan=True),
        return_completed_result=True,
    )

    completed = result[-1]
    shodan_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'shodan')
    assert shodan_execution.status == 'skipped'
    assert shodan_execution.result_count == 0
    assert shodan_execution.stop_reason == 'no-input'


@pytest.mark.asyncio
async def test_api_scan_cancellation_persists_failure_and_propagates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    saved: list[CompletedResult] = []

    class CancelledApiScanner:
        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')

        async def do_search(self) -> None:
            raise asyncio.CancelledError

        def get_found_endpoints(self) -> set[str]:
            return {'https://example.com/api/v1'}

        def get_interesting_endpoints(self) -> set[str]:
            return {'https://example.com/api/v1'}

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', CancelledApiScanner)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(
                api_scan=True,
                domain='example.com',
                quiet=True,
                wordlist=str(wordlist),
            ),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'api-scan')
    assert execution.status == 'partial'
    assert execution.result_count == 3
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert {(observation.kind, observation.value) for observation in execution.observations} == {
        ('api-endpoint', 'https://example.com/api/v1'),
        ('interesting-url', 'https://example.com/api/v1'),
        ('url', 'https://example.com/api/v1'),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('raised_error', 'failure_stage', 'expected_status', 'expected_count'),
    [
        (RuntimeError('scan failed'), 'search', 'partial', 3),
        (MissingKey('API endpoints'), 'init', 'failed', 0),
        (RuntimeError('getter failed'), 'getter', 'partial', 3),
    ],
)
async def test_api_scan_raised_failure_is_persisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raised_error: Exception,
    failure_stage: str,
    expected_status: str,
    expected_count: int,
) -> None:
    class FailedApiScanner:
        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')
            self.scan_error_type = None
            self.request_error_count = 0
            self.request_error_types: set[str] = set()
            if failure_stage == 'init':
                raise raised_error

        async def do_search(self) -> None:
            if failure_stage == 'search':
                raise raised_error

        def get_found_endpoints(self) -> set[str]:
            if failure_stage == 'getter':
                raise raised_error
            return {'https://example.com/api/v1'}

        def get_interesting_endpoints(self) -> set[str]:
            return {'https://example.com/api/v1'}

        def get_auth_required(self) -> dict:
            return {}

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict:
            return {}

        def get_methods(self) -> set[str]:
            return set()

        def get_status_codes(self) -> set[int]:
            return set()

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FailedApiScanner)

    result = await theharvester_main.start(
        EnumerationOptions(api_scan=True, domain='example.com', quiet=True, wordlist=str(wordlist)),
        return_completed_result=True,
    )

    executions = [item for item in result[-1].active_evidence.executions if item.action == 'api-scan']
    assert len(executions) == 1
    execution = executions[0]
    assert execution.status == expected_status
    assert execution.result_count == expected_count
    assert execution.error_type == type(raised_error).__name__
    assert execution.stop_reason == 'scan-error'
    if failure_stage == 'getter':
        assert {(observation.kind, observation.value) for observation in execution.observations} == {
            ('api-endpoint', 'https://example.com/api/v1'),
            ('interesting-url', 'https://example.com/api/v1'),
            ('url', 'https://example.com/api/v1'),
        }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('raised_error', 'failure_stage', 'expected_reason'),
    [
        (asyncio.CancelledError(), 'process', 'cancelled'),
        (RuntimeError('scan failed'), 'process', 'scan-error'),
        (RuntimeError('constructor failed'), 'init', 'scan-error'),
        (RuntimeError('getter failed'), 'getter', 'scan-error'),
    ],
)
async def test_takeover_failure_persists_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
    raised_error: BaseException,
    failure_stage: str,
    expected_reason: str,
) -> None:
    saved: list[CompletedResult] = []

    class CancelledTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            self.request_error_count = 0
            self.request_error_types: set[str] = set()
            self.scan_error_type = None
            if failure_stage == 'init':
                raise raised_error

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, _proxy: bool = False, **_kwargs) -> None:
            if failure_stage == 'process':
                raise raised_error

        async def get_takeover_results(self) -> dict:
            if failure_stage == 'getter':
                raise raised_error
            return {}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', CancelledTakeOver)

    with pytest.raises(type(raised_error)):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', quiet=True, source='crtsh', take_over=True),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'takeover')
    assert execution.status == 'failed'
    assert execution.result_count == 0
    assert execution.error_type == type(raised_error).__name__
    assert execution.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_shodan_cancellation_persists_failure_and_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    saved: list[CompletedResult] = []

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['api.example.com:192.0.2.10', 'www.example.com:192.0.2.11'],
                ['api.example.com', 'www.example.com'],
                ['192.0.2.10', '192.0.2.11'],
            )

    class CancelledShodan:
        error_type = None

        async def search_ip(self, ip: str) -> dict:
            return {ip: {'ports': [443]}}

    async def cancel_during_throttle(_seconds: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', CancelledShodan)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', cancel_during_throttle)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(
                dns_resolve='192.0.2.53',
                domain='example.com',
                quiet=True,
                shodan=True,
                source='crtsh',
            ),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'shodan')
    assert execution.status == 'partial'
    assert execution.result_count == 1
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['takeover', 'shodan'])
async def test_direct_action_checkpoint_cancellation_persists_and_propagates(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    saved: list[CompletedResult] = []

    class FakeTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            self.request_count = 1
            self.request_error_count = 0
            self.request_error_types: set[str] = set()
            self.scan_error_type = None

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False

        async def get_takeover_results(self) -> dict:
            return {}

    class FakeShodan:
        error_type = None

        async def search_ip(self, ip: str) -> dict:
            return {ip: {'ports': [443]}}

    async def cancel_after_action(result: CompletedResult) -> None:
        if any(execution.action == action for execution in result.active_evidence.executions):
            raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)

    options = EnumerationOptions(
        dns_resolve='192.0.2.53' if action == 'shodan' else '',
        domain='example.com',
        quiet=True,
        shodan=action == 'shodan',
        source='crtsh',
        take_over=action == 'takeover',
    )
    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            options,
            completed_result_checkpoint=cancel_after_action,
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == action)
    assert execution.status == 'completed'


@pytest.mark.asyncio
async def test_recursive_dns_results_reach_completed_output_without_changing_legacy_shapes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []
    captured: list[tuple[str, tuple[str, ...], int, int]] = []
    closed: list[str] = []
    output_path = tmp_path / 'recursive-dns'

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.1'], ['api.example.com'], ['192.0.2.1']

    class FakeResolver:
        def __init__(self, nameserver: str, target: str) -> None:
            self.name = nameserver
            assert target == 'example.com'

        async def close(self) -> None:
            closed.append(self.name)

    async def fake_recursive(target, seeds, _labels, _resolvers, limits):
        captured.append((target, tuple(seeds), limits.depth, limits.query_limit))
        return RecursiveDNSResult(
            findings=(
                RecursiveDNSFinding(
                    'dev.api.example.com',
                    'api.example.com',
                    HostDnsRecords(ipv4=('192.0.2.2',), ipv6=('2001:db8::2',)),
                    ('ptr.example.net',),
                ),
            ),
            query_count=24,
            depth_reached=1,
            zero_yield_batches=0,
            stop_reason='depth-limit',
            classifications=(
                RecursiveDNSClassification(
                    'unused.api.example.com',
                    'api.example.com',
                    Addressability.NOT_CURRENT,
                    HostDnsRecords(cnames=('missing.vendor.test',)),
                    ('legacy-ptr.example.net',),
                ),
            ),
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', fake_recursive)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '--dns-recursive-depth',
            '1',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured == [('example.com', ('api.example.com',), 1, 3_000)]
    assert sorted(closed) == ['192.0.2.53', '192.0.2.54', '192.0.2.55']
    assert completed
    assert ('hostname', 'dev.api.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.2') in completed[0].results
    assert ('ip-address', '2001:db8::2') in completed[0].results
    assert (
        'dns-recursive-finding',
        json.dumps(
            {
                'addresses': ['192.0.2.2', '2001:db8::2'],
                'hostname': 'dev.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert set(json.loads(output_path.with_suffix('.json').read_text())['hosts']) >= {
        'dev.api.example.com:192.0.2.2',
        'dev.api.example.com:2001:db8::2',
    }
    xml_pairs = [
        (element.findtext('hostname'), element.findtext('ip'))
        for element in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('host')
    ]
    assert xml_pairs.count(('dev.api.example.com', '192.0.2.2')) == 1
    assert xml_pairs.count(('dev.api.example.com', '2001:db8::2')) == 1
    assert not any(ip is not None and ',' in ip for _host, ip in xml_pairs)
    assert (
        'dns-recursive-summary',
        json.dumps(
            {'depth_reached': 1, 'query_count': 24, 'stop_reason': 'depth-limit', 'zero_yield_batches': 0},
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert (
        'dns-recursive-classification',
        json.dumps(
            {
                'addressability': 'not-currently-addressable',
                'addresses': [],
                'cnames': ['missing.vendor.test'],
                'hostname': 'unused.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['legacy-ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    recursive_execution = next(
        execution for execution in completed[0].active_evidence.executions if execution.action == 'dns-recursive'
    )
    assert recursive_execution.status == 'completed'
    assert recursive_execution.stop_reason == 'depth-limit'
    assert recursive_execution.result_count == 6
    assert {(observation.kind, observation.value) for observation in recursive_execution.observations} >= {
        ('hostname', 'dev.api.example.com'),
        ('ip-address', '192.0.2.2'),
        ('ip-address', '2001:db8::2'),
    }


@pytest.mark.asyncio
async def test_requested_recursive_dns_without_seed_hosts_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    async def unexpected_recursive(*_args, **_kwargs):
        raise AssertionError('recursive discovery must not start without seed hostnames')

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', unexpected_recursive)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            source='',
            dns_resolve='192.0.2.53,192.0.2.54,192.0.2.55',
            dns_recursive_depth=1,
            quiet=True,
        ),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    recursive_execution = next(
        execution for execution in completed.active_evidence.executions if execution.action == 'dns-recursive'
    )
    assert recursive_execution.status == 'skipped'
    assert recursive_execution.result_count == 0
    assert recursive_execution.stop_reason == 'no-input'


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
@pytest.mark.asyncio
async def test_recursive_dns_closes_resolvers_on_failure_and_preserves_cancellation(
    monkeypatch: pytest.MonkeyPatch, error_type: type[BaseException]
) -> None:
    closed: list[str] = []
    completed: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.1'], ['api.example.com'], ['192.0.2.1']

    class FakeResolver:
        def __init__(self, nameserver: str, _target: str) -> None:
            self.name = nameserver

        async def close(self) -> None:
            closed.append(self.name)

    async def fail_recursive(*_args, **_kwargs):
        raise error_type()

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', fail_recursive)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '--dns-recursive-depth',
            '1',
        ],
    )

    if issubclass(error_type, asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            await theharvester_main.start()
    else:
        with pytest.raises(SystemExit) as exit_info:
            await theharvester_main.start()
        assert exit_info.value.code == 0

    assert sorted(closed) == ['192.0.2.53', '192.0.2.54', '192.0.2.55']
    assert len(completed) == 1
    recursive_execution = next(
        execution for execution in completed[0].active_evidence.executions if execution.action == 'dns-recursive'
    )
    assert recursive_execution.status == 'failed'
    assert recursive_execution.error_type == error_type.__name__
    assert recursive_execution.stop_reason == ('cancelled' if issubclass(error_type, asyncio.CancelledError) else None)
