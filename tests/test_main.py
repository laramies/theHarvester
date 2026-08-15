import asyncio
import json
import logging
import sys
import xml.etree.ElementTree as ElementTree
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest

import theHarvester.screenshot.screenshot as screenshot_module
from theHarvester import __main__ as theharvester_main
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import source_runner
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.completed_result import CompletedResult, ResultObservation, SourceExecution
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.dns_consensus import Addressability
from theHarvester.lib.enumeration import EnumerationOptions
from theHarvester.lib.hostchecker import HostDnsRecords
from theHarvester.lib.network_evidence import PrefixOriginObservation, RpkiValidationObservation
from theHarvester.lib.recursive_dns import RecursiveDNSClassification, RecursiveDNSFinding, RecursiveDNSResult
from theHarvester.lib.routeviews import RouteViewsCancelled, RouteViewsResult
from theHarvester.lib.takeover_evidence import TakeoverCandidateOutcome
from theHarvester.lib.virtual_host import (
    HarvestedVirtualHostResult,
    VirtualHostDiscoveryCancelled,
    VirtualHostObservation,
)


@pytest.mark.asyncio
async def test_cli_help_explains_proxy_and_direct_action_scope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    help_text = ' '.join(capsys.readouterr().out.split())
    assert exit_info.value.code == 0
    assert (
        'Use proxies.yaml for supported discovery-source, Shodan, and takeover requests. Takeover fails closed if no '
        'proxy is available.' in help_text
    )
    assert 'Query the Shodan Host API for discovered IPs, using configured proxies when enabled.' in help_text
    assert (
        'Enrich discovered IPs with sourced ASN attribution, or an explicitly targeted ASN, IP, or prefix, through '
        'RouteViews.' in help_text
    )
    assert 'Exclude hostname results while retaining other result types returned by selected sources.' in help_text
    assert 'Accepted for compatibility but currently unused; use --dns-resolvers to select resolvers.' in help_text
    assert 'Select resolver IPs for DNS actions without enabling hostname resolution.' in help_text
    assert 'text file with one IP per line' in help_text
    assert 'Perform PTR lookups across the /24 network containing each discovered IPv4 address.' in help_text
    assert 'Multiple capabilities select the union of matching sources; they do not filter returned fields.' in help_text
    assert 'Check common API paths with GET, HEAD, and OPTIONS.' in help_text
    assert 'Requests follow redirects.' in help_text
    assert 'virtual host discovery' in help_text
    assert 'P2 direct interaction (active reconnaissance): sends direct HTTP and TLS requests.' in help_text
    assert 'For normal use, pass only --vhost; bounded safety defaults apply automatically.' in help_text
    assert 'virtual host advanced controls' in help_text
    assert 'Candidate names are never resolved through DNS.' in help_text
    assert '-j SOURCE_WORKERS' in help_text
    assert '--source-workers SOURCE_WORKERS' in help_text
    assert 'Indicators are not confirmed takeovers.' in help_text


def _confirmed_vhost(endpoint: str = 'http://192.0.2.10:80/') -> VirtualHostObservation:
    return VirtualHostObservation(
        endpoint=endpoint,
        hostname='admin.example.com',
        http_host='admin.example.com',
        tls_server_name=None,
        classification='distinct',
        phase='body',
        status=200,
        location=None,
        body_sha256='a' * 64,
        body_size=5,
        body_truncated=False,
        tls_verified=None,
        error_type=None,
        distinct_signals=('body_sha256',),
        reflection_normalized=False,
        needs_confirmation=False,
        context_phase='body',
        context_status=200,
        context_location=None,
        context_body_sha256='b' * 64,
        context_body_size=5,
        context_body_truncated=False,
        control_phase='body',
        control_status=200,
        control_location=None,
        control_body_sha256='b' * 64,
        control_body_size=5,
        control_body_truncated=False,
        confirmation_body_sha256='a' * 64,
    )


def _takeover_outcome(hostname: str = 'api.example.com') -> TakeoverCandidateOutcome:
    return TakeoverCandidateOutcome.from_record(
        hostname,
        {
            'status': 'indicator',
            'dns': [
                {
                    'resolver': '1.1.1.1',
                    'cname_chain': ['missing-bucket.s3.amazonaws.com'],
                    'terminal_rcode': 'NOERROR',
                }
            ],
            'wildcard_dns': [
                {
                    'resolver': '1.1.1.1',
                    'cname_chain': [],
                    'terminal_rcode': 'NXDOMAIN',
                }
            ],
            'http': [{'scheme': 'https', 'status': 404}],
            'indicators': [
                {
                    'classification': 'vulnerable-indicator',
                    'service': 'AWS/S3',
                    'rule_id': 'aws-s3',
                    'rule_revision': 'takeover-rules-v1',
                    'scheme': 'https',
                    'matched': ['body:BucketName', 'body:The specified bucket does not exist'],
                }
            ],
            'error_types': [],
        },
    )


@pytest.mark.asyncio
async def test_virtual_host_action_reaches_completed_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    async def fake_discover(**kwargs: object) -> HarvestedVirtualHostResult:
        calls.append(kwargs)
        return HarvestedVirtualHostResult((_confirmed_vhost(),), 5, 1, 1, 1, 1, 'completed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', fake_discover, raising=False)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            vhost_endpoint='http://192.0.2.10/',
            vhost_candidates=('admin.example.com',),
        ),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert calls[0]['scope'] == 'example.com'
    assert calls[0]['addresses'] == ()
    assert calls[0]['candidates'] == ('admin.example.com',)
    assert calls[0]['endpoint_override'] == 'http://192.0.2.10:80/'
    execution = next(item for item in completed.active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'completed'
    assert {(item.kind, item.value) for item in execution.observations} == {('hostname', 'admin.example.com')}
    assert completed.virtual_hosts == (_confirmed_vhost(),)


@pytest.mark.asyncio
async def test_virtual_host_inputs_fail_before_result_store_initialization(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnexpectedResultStore:
        def __init__(self, *_args: object) -> None:
            raise AssertionError('result store initialization must follow virtual-host validation')

    monkeypatch.setattr(theharvester_main, 'ResultStore', UnexpectedResultStore)

    with pytest.raises(ValueError, match='outside authorized scope'):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                vhost_endpoint='https://192.0.2.10/',
                vhost_candidates=('admin.attacker.test',),
            )
        )

    with pytest.raises(ValueError, match='direct transport only'):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                proxies=True,
                vhost_endpoint='https://192.0.2.10/',
                vhost_candidates=('admin.example.com',),
            )
        )


@pytest.mark.asyncio
async def test_virtual_host_action_uses_harvested_hostnames_and_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'admin.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('admin.example.com', '192.0.2.10')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    async def fake_discover(**kwargs: object) -> HarvestedVirtualHostResult:
        calls.append(kwargs)
        return HarvestedVirtualHostResult((), 5, 1, 1, 1, 1, 'completed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', fake_discover)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, source='rapiddns', vhost=True),
        return_completed_result=True,
    )

    assert calls[0]['addresses'] == ('192.0.2.10',)
    assert calls[0]['candidates'] == ('admin.example.com',)
    execution = next(item for item in response[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'completed'
    assert execution.result_count == 0


@pytest.mark.asyncio
async def test_virtual_host_action_explains_missing_harvested_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, vhost_candidates=('admin.example.com',)),
        return_completed_result=True,
    )

    execution = next(item for item in response[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'skipped'
    assert execution.stop_reason == 'no-endpoints'


@pytest.mark.asyncio
async def test_virtual_host_action_reports_all_request_errors_as_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failed_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult(
            observations=(),
            request_count=5,
            endpoint_count=1,
            total_endpoint_count=1,
            candidate_endpoint_count=1,
            total_candidate_endpoint_count=1,
            stop_reason='request-errors',
            request_error_count=5,
            request_error_types=('TimeoutError',),
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', failed_discovery)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            vhost_endpoint='http://192.0.2.10/',
            vhost_candidates=('admin.example.com',),
        ),
        return_completed_result=True,
    )

    execution = next(item for item in response[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'failed'
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == 'request-errors'


@pytest.mark.asyncio
async def test_virtual_host_action_reports_mixed_request_errors_without_a_finding_as_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult(
            observations=(),
            request_count=5,
            endpoint_count=1,
            total_endpoint_count=1,
            candidate_endpoint_count=1,
            total_candidate_endpoint_count=1,
            stop_reason='request-errors',
            request_error_count=1,
            request_error_types=('TimeoutError',),
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', failed_discovery)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            vhost_endpoint='http://192.0.2.10/',
            vhost_candidates=('admin.example.com',),
        ),
        return_completed_result=True,
    )

    execution = next(item for item in response[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'failed'
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == 'request-errors'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('stop_reason', 'scan_error_type', 'expected_error_type'),
    [
        ('request-errors', None, 'TimeoutError'),
        ('scan-error', 'ConnectionError', 'ConnectionError'),
    ],
)
async def test_virtual_host_action_reports_mixed_or_scan_errors_as_partial(
    monkeypatch: pytest.MonkeyPatch,
    stop_reason: str,
    scan_error_type: str | None,
    expected_error_type: str,
) -> None:
    saved: list[CompletedResult] = []

    async def partial_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult(
            observations=(_confirmed_vhost(),),
            request_count=5,
            endpoint_count=1,
            total_endpoint_count=1,
            candidate_endpoint_count=1,
            total_candidate_endpoint_count=1,
            stop_reason=stop_reason,
            request_error_count=1,
            request_error_types=('TimeoutError',),
            scan_error_type=scan_error_type,
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', partial_discovery)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            vhost_endpoint='http://192.0.2.10/',
            vhost_candidates=('admin.example.com',),
        ),
        return_completed_result=True,
    )

    completed = response[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'partial'
    assert execution.error_type == expected_error_type
    assert execution.stop_reason == stop_reason
    assert completed.virtual_hosts == (_confirmed_vhost(),)
    assert saved[-1].virtual_hosts == (_confirmed_vhost(),)


@pytest.mark.asyncio
async def test_virtual_host_cancellation_persists_partial_observations_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved: list[CompletedResult] = []
    partial = HarvestedVirtualHostResult(
        observations=(_confirmed_vhost(),),
        request_count=5,
        endpoint_count=1,
        total_endpoint_count=2,
        candidate_endpoint_count=1,
        total_candidate_endpoint_count=2,
        stop_reason='cancelled',
        request_error_count=1,
        request_error_types=('TimeoutError',),
        scan_error_type='CancelledError',
    )

    async def cancelled_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        raise VirtualHostDiscoveryCancelled(partial)

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', cancelled_discovery)

    with pytest.raises(VirtualHostDiscoveryCancelled):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                quiet=True,
                vhost_endpoint='http://192.0.2.10/',
                vhost_candidates=('admin.example.com',),
            ),
            return_completed_result=True,
        )

    completed = saved[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'partial'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert completed.virtual_hosts == (_confirmed_vhost(),)


@pytest.mark.asyncio
async def test_virtual_host_cancellation_persists_failure_and_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    saved: list[CompletedResult] = []

    async def cancelled_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', cancelled_discovery)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                quiet=True,
                vhost_endpoint='http://192.0.2.10/',
                vhost_candidates=('admin.example.com',),
            ),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'failed'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
async def test_virtual_host_carried_cancellation_without_a_finding_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved: list[CompletedResult] = []
    cancelled = HarvestedVirtualHostResult(
        observations=(),
        request_count=5,
        endpoint_count=1,
        total_endpoint_count=2,
        candidate_endpoint_count=1,
        total_candidate_endpoint_count=2,
        stop_reason='cancelled',
        scan_error_type='CancelledError',
    )

    async def cancelled_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        raise VirtualHostDiscoveryCancelled(cancelled)

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', cancelled_discovery)

    with pytest.raises(VirtualHostDiscoveryCancelled):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                quiet=True,
                vhost_endpoint='http://192.0.2.10/',
                vhost_candidates=('admin.example.com',),
            ),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'failed'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
@pytest.mark.parametrize('stop_reason', ['request-limit', 'runtime-limit'])
async def test_virtual_host_limits_remain_partial_without_a_finding(
    monkeypatch: pytest.MonkeyPatch,
    stop_reason: str,
) -> None:
    async def limited_discovery(**_kwargs: object) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult((), 4, 1, 1, 0, 1, stop_reason)

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', limited_discovery)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            vhost_endpoint='http://192.0.2.10/',
            vhost_candidates=('admin.example.com',),
        ),
        return_completed_result=True,
    )

    execution = next(item for item in response[-1].active_evidence.executions if item.action == 'vhost')
    assert execution.status == 'partial'
    assert execution.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_virtual_host_output_keeps_legacy_lists_and_structured_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / 'vhost-report'

    async def fake_discover(**_kwargs: object) -> HarvestedVirtualHostResult:
        return HarvestedVirtualHostResult((_confirmed_vhost(),), 5, 1, 1, 1, 1, 'completed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'discover_harvested_virtual_hosts', fake_discover)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '--vhost-endpoint',
            'http://192.0.2.10/',
            '--vhost-candidate',
            'admin.example.com',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert json.loads(output_path.with_suffix('.json').read_text())['vhosts'] == ['admin.example.com']
    assert [item.text for item in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('vhost')] == [
        'admin.example.com'
    ]
    jsonl = [json.loads(line) for line in output_path.with_suffix('.jsonl').read_text().splitlines()]
    finding = next(item for item in jsonl if item['type'] == 'hostname')
    assert finding['value'] == 'admin.example.com'
    assert finding['actions'] == ['vhost']
    assert len(finding['observations']) == 1
    assert finding['observations'][0]['endpoint'] == 'http://192.0.2.10:80/'


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
        calls = 0

        def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']
            assert hosts == ['api.example.com', 'crt.example.com', 'reported.example.com']
            type(self).calls += 1
            self.query_error_count = 1
            self.query_error_types = {'TimeoutError'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return (
                [
                    'api.example.com:192.0.2.10',
                    'crt.example.com:192.0.2.30',
                    'reported.example.com:192.0.2.21',
                ],
                ['api.example.com', 'crt.example.com', 'reported.example.com'],
                ['192.0.2.10', '192.0.2.21', '192.0.2.30'],
            )

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeCrtsh)
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
    assert ('ip', '192.0.2.10') in completed[0].results
    assert ('ip', '192.0.2.20') in completed[0].results
    assert ('ip', '192.0.2.21') in completed[0].results
    assert ('ip', '192.0.2.30') in completed[0].results
    assert FakeChecker.calls == 1
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
        ('ip', '192.0.2.10'),
        ('ip', '192.0.2.21'),
        ('ip', '192.0.2.30'),
    }
    assert ('ip', '192.0.2.20') not in {(observation.kind, observation.value) for observation in dns_execution.observations}
    assert completed[0].evidence_dict()['status'] == 'partial'
    assert {(observation.source, observation.kind, observation.value) for observation in completed[0].observations} >= {
        ('crtsh', 'hostname', 'crt.example.com'),
        ('rapiddns', 'hostname', 'api.example.com'),
        ('rapiddns', 'hostname', 'reported.example.com'),
        ('rapiddns', 'ip', '192.0.2.20'),
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
async def test_provider_resolved_hostname_survives_no_answer_dns_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: CompletedResult) -> None:
            return None

    class FakeHackerTarget:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'provider.example.com'}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.20'}

    class NoAnswerChecker:
        calls = 0
        completed_count = 1
        query_error_count = 0
        query_error_types: set[str] = set()
        stop_reason = None

        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert hosts == ['provider.example.com']
            type(self).calls += 1

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.hackertarget, 'SearchHackerTarget', FakeHackerTarget)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', NoAnswerChecker)

    output_path = tmp_path / 'provider-no-answer'
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'hackertarget',
            '-r',
            '192.0.2.53',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert NoAnswerChecker.calls == 1
    assert json.loads(output_path.with_suffix('.json').read_text())['hosts'] == ['provider.example.com']


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
        ('ip', '192.0.2.10'),
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
    assert ('ip', '192.0.2.10') in completed.results
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
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', FakeSource)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeSource)
    monkeypatch.setattr(source_runner.shodanct, 'SearchShodanCt', FakeSource)
    monkeypatch.setattr(source_runner.subdomaincenter, 'SubdomainCenter', FakeSource)
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
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', CancelledSource)

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
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', FakeSource)
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
async def test_dns_resolve_budget_stop_retains_partial_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
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

    class LimitedChecker:
        completed_count = 1
        query_error_count = 0
        query_error_types: set[str] = set()
        stop_reason = 'query-limit'

        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert hosts == ['api.example.com']

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', FakeSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', LimitedChecker)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='certspotter', dns_resolve='192.0.2.53', quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    execution = completed.active_evidence.executions[0]
    assert execution.status == 'partial'
    assert execution.stop_reason == 'query-limit'
    assert ('ip', '192.0.2.10') in completed.results


@pytest.mark.asyncio
async def test_explicit_dns_resolvers_normalizing_empty_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
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

    class UnexpectedChecker:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError('explicit invalid resolvers must not fall back to system DNS')

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', FakeSource)
    monkeypatch.setattr(theharvester_main, 'normalize_resolver_addresses', lambda _values: [])
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', UnexpectedChecker)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='certspotter', dns_resolve='invalid-resolver', quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert ('hostname', 'api.example.com') in completed.results
    execution = completed.active_evidence.executions[0]
    assert execution.status == 'skipped'
    assert execution.stop_reason == 'no-valid-resolvers'


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
        ipranges: tuple[str, ...],
        callback,
        nameservers: list[str] | None = None,
        error_types: set[str] | None = None,
    ) -> theharvester_main.dnssearch.ReverseDNSResult:
        assert ipranges == ('192.0.2.0/24',)
        assert nameservers is None
        callback('PTR.example.com.')
        return theharvester_main.dnssearch.ReverseDNSResult(254, 254)

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecard)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_ip_ranges', fake_reverse)

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
async def test_dns_lookup_cancellation_persists_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []

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
        ipranges: tuple[str, ...],
        callback,
        nameservers: list[str] | None = None,
        error_types: set[str] | None = None,
    ) -> None:
        assert nameservers is None
        assert ipranges == ('192.0.2.0/24', '198.51.100.0/24')
        callback('partial.example.com')
        raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecard)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_ip_ranges', fake_reverse)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='securityscorecard', dns_lookup=True, quiet=True),
            persist_completed_result=True,
        )

    assert len(completed) == 1
    execution = completed[0].active_evidence.executions[0]
    assert execution.action == 'dns-lookup'
    assert execution.status == 'partial'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert [(observation.kind, observation.value) for observation in execution.observations] == [
        ('hostname', 'partial.example.com')
    ]


@pytest.mark.parametrize(
    ('source', 'module', 'constructor_name'),
    [
        ('projectdiscovery', source_runner.projectdiscovery, 'SearchDiscovery'),
        ('bevigil', source_runner.bevigil, 'SearchBeVigil'),
        ('builtwith', source_runner.builtwith, 'SearchBuiltWith'),
        ('hudsonrock', source_runner.hudsonrocksearch, 'SearchHudsonRock'),
        ('shodan', source_runner.shodansearch, 'SearchShodan'),
    ],
)
@pytest.mark.asyncio
async def test_constructor_missing_credentials_are_persisted_as_skipped_source(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    module: ModuleType,
    constructor_name: str,
) -> None:
    saved_results: list[CompletedResult] = []

    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved_results.append(result)

    class MissingCredentialSource:
        construction_count = 0

        def __init__(self, _word: str) -> None:
            type(self).construction_count += 1
            raise MissingKey(source)

    monkeypatch.setattr(theharvester_main, 'ResultStore', RecordingResultStore)
    monkeypatch.setattr(module, constructor_name, MissingCredentialSource)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source=source, quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert saved_results == [completed]
    assert MissingCredentialSource.construction_count == 1
    assert len(completed.source_executions) == 1
    execution = completed.source_executions[0]
    assert execution.source == source
    assert execution.status == 'skipped'
    assert execution.result_count == 0
    assert execution.error_type == 'MissingKeyError'
    assert execution.stop_reason == 'missing-credentials'


@pytest.mark.asyncio
async def test_target_only_source_reports_search_progress_at_the_cli_seam(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class EmptyBeVigil:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return set()

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.bevigil, 'SearchBeVigil', EmptyBeVigil)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', 'bevigil'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert '[*] Searching Bevigil.' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_source_progress_waits_for_runner_admission(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sources = ('certspotter', 'crt-name', 'crtsh', 'dymo')
    requested_workers = 3
    admitted_sources = sources[:requested_workers]
    constructed: list[str] = []
    processing: set[str] = set()
    admitted = asyncio.Event()
    release = asyncio.Event()

    class GatedSource:
        def __init__(self, source: str) -> None:
            self.source = source

        async def process(self, _proxy: bool) -> None:
            processing.add(self.source)
            if len(processing) == requested_workers:
                admitted.set()
            await release.wait()

        async def get_hostnames(self) -> set[str]:
            return set()

    def factory(source: str) -> source_runner.SourceFactory:
        def create(_request: source_runner.SourceRequest) -> GatedSource:
            constructed.append(source)
            return GatedSource(source)

        return create

    for source in sources:
        monkeypatch.setitem(source_runner.SOURCE_FACTORIES, source, factory(source))
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    theharvester_main.configure_logging(verbose=False)

    task = asyncio.create_task(
        theharvester_main.start(
            EnumerationOptions(domain='example.test', source=','.join(sources), source_workers=requested_workers, quiet=False),
            return_completed_result=True,
        )
    )
    await asyncio.wait_for(admitted.wait(), timeout=1)
    interim_output = capsys.readouterr().out
    release.set()
    await task

    assert constructed[:requested_workers] == list(admitted_sources)
    assert all(f'[*] Searching {source[0].upper() + source[1:]}.' in interim_output for source in admitted_sources)
    assert '[*] Searching Dymo.' not in interim_output


@pytest.mark.asyncio
async def test_source_completion_reports_verbose_terminal_summary(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class CompletedCertSpotter:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.test'}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.certspottersearch, 'SearchCertspoter', lambda _word: CompletedCertSpotter())
    caplog.set_level(logging.INFO, logger='theHarvester.__main__')

    await theharvester_main.start(
        EnumerationOptions(domain='example.test', source='certspotter', quiet=True),
        return_completed_result=True,
    )

    assert any(
        message.startswith('Source certspotter finished in ') and message.endswith('s: status=completed; results=1')
        for message in caplog.messages
    )


@pytest.mark.parametrize(
    ('error', 'expected_status', 'expected_error_type', 'expected_stop_reason', 'expected_diagnostic'),
    [
        (
            MissingKey('sensitive-provider-detail'),
            'skipped',
            'MissingKeyError',
            'missing-credentials',
            '[!] Source bevigil skipped: missing credentials.',
        ),
        (
            RuntimeError('sensitive-provider-detail'),
            'failed',
            'RuntimeError',
            None,
            '[!] Source bevigil failed: RuntimeError.',
        ),
    ],
)
@pytest.mark.asyncio
async def test_target_only_constructor_failure_reports_sanitized_cli_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    expected_status: str,
    expected_error_type: str,
    expected_stop_reason: str | None,
    expected_diagnostic: str,
) -> None:
    saved_results: list[CompletedResult] = []

    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved_results.append(result)

    class BrokenBeVigil:
        def __init__(self, _word: str) -> None:
            raise error

    monkeypatch.setattr(theharvester_main, 'ResultStore', RecordingResultStore)
    monkeypatch.setattr(source_runner.bevigil, 'SearchBeVigil', BrokenBeVigil)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', 'bevigil'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    output = capsys.readouterr().out
    assert exit_info.value.code == 0
    assert expected_diagnostic in output
    assert '[*] Searching Bevigil.' not in output
    assert 'sensitive-provider-detail' not in output
    execution = saved_results[-1].source_executions[0]
    assert execution.status == expected_status
    assert execution.error_type == expected_error_type
    assert execution.stop_reason == expected_stop_reason


@pytest.mark.asyncio
async def test_partial_source_reports_sanitized_cli_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class PartialBeVigil:
        async def process(self, _proxy: bool) -> None:
            raise RuntimeError('sensitive-provider-detail')

        async def get_hostnames(self) -> set[str]:
            return {'partial.example.test'}

        async def get_urls(self) -> set[str]:
            return set()

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.bevigil, 'SearchBeVigil', lambda _word: PartialBeVigil())
    theharvester_main.configure_logging(verbose=False)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.test', source='bevigil', quiet=False),
        return_completed_result=True,
    )

    output = capsys.readouterr().out
    assert '[!] Source bevigil partial: RuntimeError.' in output
    assert 'sensitive-provider-detail' not in output
    assert response[-1].source_executions[0].status == 'partial'


@pytest.mark.asyncio
async def test_source_checkpoint_failure_does_not_log_sensitive_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class EmptyBeVigil:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return set()

    checkpoint_calls = 0

    async def broken_checkpoint(_result: CompletedResult) -> None:
        nonlocal checkpoint_calls
        checkpoint_calls += 1
        if checkpoint_calls == 1:
            raise RuntimeError('sensitive-checkpoint-detail')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.bevigil, 'SearchBeVigil', lambda _word: EmptyBeVigil())
    theharvester_main.configure_logging(verbose=False)

    await theharvester_main.start(
        EnumerationOptions(domain='example.test', source='bevigil', quiet=True),
        completed_result_checkpoint=broken_checkpoint,
        return_completed_result=True,
    )

    output = capsys.readouterr().out
    assert 'An error occurred while committing bevigil: RuntimeError.' in output
    assert 'sensitive-checkpoint-detail' not in output


@pytest.mark.asyncio
async def test_source_cancellation_does_not_announce_never_started_queued_source(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sources = ('certspotter', 'crt-name', 'crtsh', 'dymo')
    requested_workers = 3
    cancellation = asyncio.CancelledError('source cancelled')
    constructed: list[str] = []
    processing: set[str] = set()
    admitted = asyncio.Event()

    class CancellingSource:
        def __init__(self, source: str) -> None:
            self.source = source

        async def process(self, _proxy: bool) -> None:
            processing.add(self.source)
            if len(processing) == requested_workers:
                admitted.set()
            await admitted.wait()
            if self.source == sources[0]:
                raise cancellation
            await asyncio.Event().wait()

        async def get_hostnames(self) -> set[str]:
            return set()

    def factory(source: str) -> source_runner.SourceFactory:
        def create(_request: source_runner.SourceRequest) -> CancellingSource:
            constructed.append(source)
            return CancellingSource(source)

        return create

    for source in sources:
        monkeypatch.setitem(source_runner.SOURCE_FACTORIES, source, factory(source))
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    theharvester_main.configure_logging(verbose=False)

    with pytest.raises(asyncio.CancelledError) as raised:
        async with asyncio.timeout(1):
            await theharvester_main.start(
                EnumerationOptions(
                    domain='example.test', source=','.join(sources), source_workers=requested_workers, quiet=False
                ),
                return_completed_result=True,
            )

    output = capsys.readouterr().out
    assert raised.value is cancellation
    assert constructed == list(sources[:requested_workers])
    assert '[*] Searching Dymo.' not in output


@pytest.mark.parametrize(
    ('source', 'module', 'constructor_name'),
    [
        ('builtwith', source_runner.builtwith, 'SearchBuiltWith'),
        ('hudsonrock', source_runner.hudsonrocksearch, 'SearchHudsonRock'),
        ('shodan', source_runner.shodansearch, 'SearchShodan'),
    ],
)
@pytest.mark.asyncio
async def test_special_source_constructor_failure_uses_runner_outcome(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    module: ModuleType,
    constructor_name: str,
) -> None:
    class BrokenSource:
        def __init__(self, _word: str) -> None:
            raise RuntimeError('construction failed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(module, constructor_name, BrokenSource)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.test', source=source, quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert completed.source_executions == (
        SourceExecution(source, 'failed', completed.source_executions[0].duration_ms, 0, 'RuntimeError'),
    )


@pytest.mark.parametrize(
    ('source', 'module', 'constructor_name', 'expected_results'),
    [
        (
            'builtwith',
            source_runner.builtwith,
            'SearchBuiltWith',
            {
                ('analytics', 'Plausible'),
                ('cms', 'Wagtail'),
                ('framework', 'Django'),
                ('hostname', 'partial.example.test'),
                ('language', 'Python'),
                ('server', 'nginx'),
                ('url', 'https://partial.example.test'),
            },
        ),
        (
            'hudsonrock',
            source_runner.hudsonrocksearch,
            'SearchHudsonRock',
            {
                ('email', 'user@example.test'),
                ('hostname', 'partial.example.test'),
                ('infostealer', '{"email":"user@example.test"}'),
            },
        ),
        ('shodan', source_runner.shodansearch, 'SearchShodan', {('hostname', 'partial.example.test')}),
    ],
)
@pytest.mark.asyncio
async def test_special_source_cancellation_retains_partial_evidence_and_original_error(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    module: ModuleType,
    constructor_name: str,
    expected_results: set[tuple[str, str]],
) -> None:
    cancellation = asyncio.CancelledError(f'cancel {source}')
    saved_results: list[CompletedResult] = []

    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved_results.append(result)

    class CancellingSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            raise cancellation

        async def get_hostnames(self) -> set[str]:
            return {'partial.example.test'}

        async def get_emails(self) -> set[str]:
            return {'user@example.test'}

        async def get_ips(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return {'https://partial.example.test'}

        async def get_frameworks(self) -> set[str]:
            return {'Django'}

        async def get_languages(self) -> set[str]:
            return {'Python'}

        async def get_servers(self) -> set[str]:
            return {'nginx'}

        async def get_cms(self) -> set[str]:
            return {'Wagtail'}

        async def get_analytics(self) -> set[str]:
            return {'Plausible'}

        async def get_infostealers(self) -> list[dict[str, str]]:
            return [{'email': 'user@example.test'}]

        async def get_shodan_hosts(self) -> tuple[()]:
            return ()

    monkeypatch.setattr(theharvester_main, 'ResultStore', RecordingResultStore)
    monkeypatch.setattr(module, constructor_name, CancellingSource)

    with pytest.raises(asyncio.CancelledError) as raised:
        await theharvester_main.start(
            EnumerationOptions(domain='example.test', source=source, quiet=True),
            persist_completed_result=True,
        )

    assert raised.value is cancellation
    assert len(saved_results) == 1
    assert set(saved_results[0].results) == expected_results
    assert saved_results[0].source_executions == (
        SourceExecution(
            source,
            'partial',
            saved_results[0].source_executions[0].duration_ms,
            len(expected_results),
            'CancelledError',
            'cancelled',
        ),
    )
    assert {observation.source for observation in saved_results[0].observations} == {source}


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

        async def get_urls(self) -> set[str]:
            raise RuntimeError('provider page failed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.builtwith, 'SearchBuiltWith', PartiallyFailingBuiltWith)
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

        async def get_urls(self) -> set[str]:
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
    monkeypatch.setattr(source_runner.builtwith, 'SearchBuiltWith', PausedBuiltWith)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FastCrtsh)
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


@pytest.mark.parametrize(
    ('source', 'main_module_name', 'constructor_name'),
    [
        ('arquivo', 'arquivo', 'SearchArquivo'),
        ('baidu', 'baidusearch', 'SearchBaidu'),
        ('brave', 'bravesearch', 'SearchBrave'),
        ('censys', 'censysearch', 'SearchCensys'),
        ('commoncrawl', 'commoncrawl', 'SearchCommoncrawl'),
        ('dehashed', 'search_dehashed', 'SearchDehashed'),
        ('github-code', 'githubcode', 'SearchGithubCode'),
        ('hunter', 'huntersearch', 'SearchHunter'),
        ('mojeek', 'mojeek', 'SearchMojeek'),
        ('netlas', 'netlas', 'SearchNetlas'),
        ('rocketreach', 'rocketreach', 'SearchRocketReach'),
        ('tomba', 'tombasearch', 'SearchTomba'),
        ('waybackarchive', 'waybackarchive', 'SearchWaybackarchive'),
        ('yahoo', 'yahoosearch', 'SearchYahoo'),
        ('zoomeye', 'zoomeyesearch', 'SearchZoomEye'),
    ],
)
@pytest.mark.asyncio
async def test_limited_source_orchestration_uses_immutable_runner_request(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    main_module_name: str,
    constructor_name: str,
) -> None:
    requests: list[source_runner.SourceRequest] = []
    processed_with_proxy: list[bool] = []

    class FakeAdapter:
        execution_status = 'partial'
        stop_reason = 'provider-boundary'

        async def process(self, proxy: bool) -> None:
            processed_with_proxy.append(proxy)

        async def get_hostnames(self) -> set[str]:
            return {'sub.example.test'}

        async def get_emails(self) -> set[str]:
            return {'user@example.test'}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.1'}

        async def get_asns(self) -> set[str]:
            return {'AS64500'}

        async def get_urls(self) -> set[str]:
            return {'https://sub.example.test/evidence'}

    def runner_factory(request: source_runner.SourceRequest) -> FakeAdapter:
        requests.append(request)
        return FakeAdapter()

    def legacy_constructor(*_args: object, **_kwargs: object) -> object:
        raise AssertionError('legacy constructor branch was used')

    legacy_module = ModuleType(f'test_legacy_{main_module_name}')
    setattr(legacy_module, constructor_name, legacy_constructor)
    monkeypatch.setattr(theharvester_main, main_module_name, legacy_module, raising=False)
    monkeypatch.setitem(source_runner.SOURCE_FACTORIES, source, runner_factory)
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.test',
            source=source,
            limit=37,
            start=11,
            proxies=True,
            quiet=True,
        ),
        return_completed_result=True,
    )

    assert requests == [source_runner.SourceRequest(source, 'example.test', 37, 11, True, True)]
    assert processed_with_proxy == [True]
    execution = response[-1].source_executions[0]
    assert execution.source == source
    assert execution.status == 'partial'
    assert execution.stop_reason == 'provider-boundary'


@pytest.mark.parametrize(
    ('source', 'main_module_name', 'constructor_name'),
    [
        ('bevigil', 'bevigil', 'SearchBeVigil'),
        ('bufferoverun', 'bufferoverun', 'SearchBufferover'),
        ('certspotter', 'certspottersearch', 'SearchCertspoter'),
        ('criminalip', 'criminalip', 'SearchCriminalIP'),
        ('crt-name', 'crtname', 'SearchCrtName'),
        ('crtsh', 'crtsh', 'SearchCrtsh'),
        ('dnsdb', 'dnsdb', 'SearchDNSDB'),
        ('dnsdumpster', 'search_dnsdumpster', 'SearchDNSDumpster'),
        ('dymo', 'dymosearch', 'SearchDymo'),
        ('fofa', 'fofa', 'SearchFofa'),
        ('fullhunt', 'fullhuntsearch', 'SearchFullHunt'),
        ('gitlab', 'gitlabsearch', 'SearchGitlab'),
        ('hackertarget', 'hackertarget', 'SearchHackerTarget'),
        ('haveibeenpwned', 'haveibeenpwned', 'SearchHaveIBeenPwned'),
        ('hibpverified', 'hibpverified', 'SearchHibpVerified'),
        ('hunterhow', 'searchhunterhow', 'SearchHunterHow'),
        ('intelx', 'intelxsearch', 'SearchIntelx'),
        ('leakix', 'leakix', 'SearchLeakix'),
        ('leaklookup', 'leaklookup', 'SearchLeakLookup'),
        ('onyphe', 'onyphe', 'SearchOnyphe'),
        ('otx', 'otxsearch', 'SearchOtx'),
        ('pentesttools', 'pentesttools', 'SearchPentestTools'),
        ('projectdiscovery', 'projectdiscovery', 'SearchDiscovery'),
        ('rapiddns', 'rapiddns', 'SearchRapidDns'),
        ('robtex', 'robtex', 'SearchRobtex'),
        ('securityscorecard', 'securityscorecard', 'SearchSecurityScorecard'),
        ('securityTrails', 'securitytrailssearch', 'SearchSecuritytrail'),
        ('sherlockeye', 'sherlockeye', 'SearchSherlockeye'),
        ('shodanInternetDB', 'shodan_internetdb', 'SearchShodanInternetDB'),
        ('shodanct', 'shodanct', 'SearchShodanCt'),
        ('subdomaincenter', 'subdomaincenter', 'SubdomainCenter'),
        ('subdomainfinderc99', 'subdomainfinderc99', 'SearchSubdomainfinderc99'),
        ('thc', 'thc', 'SearchThc'),
        ('urlscan', 'urlscan', 'SearchUrlscan'),
        ('virustotal', 'virustotal', 'SearchVirustotal'),
        ('whoisxml', 'whoisxml', 'SearchWhoisXML'),
        ('windvane', 'windvane', 'SearchWindvane'),
    ],
)
@pytest.mark.asyncio
async def test_target_only_source_orchestration_uses_immutable_runner_request(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    main_module_name: str,
    constructor_name: str,
) -> None:
    requests: list[source_runner.SourceRequest] = []
    processed_with_proxy: list[bool] = []

    class FakeAdapter:
        execution_status = 'partial'
        stop_reason = 'provider-boundary'

        async def process(self, proxy: bool) -> None:
            processed_with_proxy.append(proxy)

        async def get_hostnames(self) -> set[str]:
            return {'sub.example.test'}

        async def get_emails(self) -> set[str]:
            return {'user@example.test'}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.1'}

        async def get_asns(self) -> set[str]:
            return {'AS64500'}

        async def get_urls(self) -> set[str]:
            return {'https://sub.example.test/evidence'}

        async def get_breach_names(self) -> set[str]:
            return {'Example Breach'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return set()

    def runner_factory(request: source_runner.SourceRequest) -> FakeAdapter:
        requests.append(request)
        return FakeAdapter()

    def legacy_constructor(*_args: object, **_kwargs: object) -> object:
        raise AssertionError('legacy constructor branch was used')

    legacy_module = ModuleType(f'test_legacy_{main_module_name}')
    setattr(legacy_module, constructor_name, legacy_constructor)
    monkeypatch.setattr(theharvester_main, main_module_name, legacy_module, raising=False)
    monkeypatch.setitem(source_runner.SOURCE_FACTORIES, source, runner_factory)
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)

    response = await theharvester_main.start(
        EnumerationOptions(
            domain='example.test',
            source=source,
            limit=37,
            start=11,
            proxies=True,
            quiet=True,
        ),
        return_completed_result=True,
    )

    assert requests == [source_runner.SourceRequest(source, 'example.test', 37, 11, True, True)]
    assert processed_with_proxy == [True]
    execution = response[-1].source_executions[0]
    assert execution.source == source
    assert execution.status == 'partial'
    assert execution.stop_reason == 'provider-boundary'


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
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', InvalidOutcomeCrtsh)
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

    with pytest.raises(ValueError, match='exactly three resolver addresses'):
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
    tmp_path: Path,
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
    resolvers = tmp_path / 'resolvers.txt'
    resolvers.write_text('192.0.2.53\n', encoding='utf-8')
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'www.example.com',
            '-c',
            '--dns-resolvers',
            str(resolvers),
            '--quiet',
        ],
    )
    checkpoints: list[CompletedResult] = []

    async def checkpoint(result: CompletedResult) -> None:
        checkpoints.append(result)

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start(completed_result_checkpoint=checkpoint)

    assert exit_info.value.code == 0
    completed = checkpoints[-1]
    actions = {execution.action for execution in completed.active_evidence.executions}
    assert 'dns-brute' in actions
    assert 'dns-resolve' not in actions


class _FakeScreenshotBatch:
    async def reachable_targets(self, targets: list[str]) -> list[tuple[str, str]]:
        reachable: list[tuple[str, str]] = []
        for subject in targets:
            final_url, status = await self.visit(subject)
            if status:
                reachable.append((subject, final_url))
        return reachable

    async def capture_targets(self, targets, record) -> None:
        async def capture(subject: str, final_url: str) -> tuple[str, str, Path]:
            output_path = self.screenshot_path(subject)
            return subject, await self.take_screenshot(final_url, output_path=output_path), output_path

        tasks = [asyncio.create_task(capture(*target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await record(*await task)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    await record(*outcome)
            raise
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


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

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            visited.add(host)
            return host, 'https'

        async def take_screenshot(self, host: str, *, output_path: Path | None = None) -> str:
            path = output_path or self.screenshot_path(host)
            path.write_bytes(b'png')
            return f'https://{host}'

        def screenshot_path(self, host: str) -> Path:
            return Path(self.output) / f'{host.removeprefix("https://")}.png'

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
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


@pytest.mark.asyncio
async def test_source_worker_count_reaches_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_workers: list[int] = []

    async def fake_run_source_jobs(_jobs, *, workers: int, **_kwargs):
        captured_workers.append(workers)
        return ()

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'run_source_jobs', fake_run_source_jobs)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.test', '-b', 'crtsh', '-j', '7', '--quiet'],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured_workers == [7]


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
async def test_screenshot_scan_uses_one_bounded_reachability_and_capture_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lifecycle_calls: list[str] = []

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            raise AssertionError('the scan must not launch a separate installation-check browser')

        async def reachable_targets(self, targets: list[str]) -> list[tuple[str, str]]:
            lifecycle_calls.append('reachability')
            assert targets == ['api.example.test']
            return [('api.example.test', 'https://login.example.net/session')]

        async def capture_targets(self, targets, record) -> None:
            lifecycle_calls.append('capture')
            assert targets == [('api.example.test', 'https://login.example.net/session')]
            output_path = self.screenshot_path('api.example.test')
            output_path.write_bytes(b'png')
            await record('api.example.test', 'https://login.example.net/session', output_path)

        def screenshot_path(self, subject: str) -> Path:
            return Path(self.output) / f'{subject}.png'

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(domain='api.example.test', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    assert lifecycle_calls == ['reachability', 'capture']
    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'completed'
    assert execution.artifacts[0].subject_value == 'api.example.test'


@pytest.mark.asyncio
async def test_screenshot_cancellation_finishes_owned_artifact_record_before_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    saved: list[CompletedResult] = []
    record_started = asyncio.Event()
    release_record = asyncio.Event()
    original_read_bytes = theharvester_main.anyio.Path.read_bytes

    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved.append(result)

    class Page:
        async def goto(self, *_args, **_kwargs) -> None:
            return None

        async def screenshot(self, *, path: Path) -> None:
            path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture

        async def close(self) -> None:
            return None

    class Context:
        async def new_page(self) -> Page:
            return Page()

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self) -> Context:
            return Context()

        async def close(self) -> None:
            return None

    class Playwright:
        chromium = None

        def __init__(self) -> None:
            self.chromium = self

        async def launch(self, **_kwargs) -> Browser:
            return Browser()

    class Manager:
        async def __aenter__(self) -> Playwright:
            return Playwright()

        async def __aexit__(self, *_args) -> None:
            return None

    async def reachable_targets(_self, targets: list[str]) -> list[tuple[str, str]]:
        assert targets == ['api.example.test']
        return [('api.example.test', 'https://api.example.test')]

    async def delayed_read_bytes(path) -> bytes:
        if path.name == 'api.example.test.png':
            record_started.set()
            await release_record.wait()
        return await original_read_bytes(path)

    monkeypatch.setattr(theharvester_main, 'ResultStore', RecordingResultStore)
    monkeypatch.setattr(screenshot_module, 'async_playwright', lambda: Manager())
    monkeypatch.setattr(screenshot_module.ScreenShotter, 'reachable_targets', reachable_targets)
    monkeypatch.setattr(theharvester_main.anyio.Path, 'read_bytes', delayed_read_bytes)

    operation = asyncio.create_task(
        theharvester_main.start(
            EnumerationOptions(domain='api.example.test', screenshot=str(tmp_path), quiet=True),
            return_completed_result=True,
        )
    )
    await asyncio.wait_for(record_started.wait(), timeout=1)
    operation.cancel('operator-stop')
    await asyncio.sleep(0)
    release_record.set()
    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await operation

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'partial'
    assert execution.stop_reason == 'cancelled'
    assert execution.artifacts[0].subject_value == 'api.example.test'
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('screenshot-')]


@pytest.mark.asyncio
async def test_screenshot_cleanup_failure_marks_the_action_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    page = MagicMock()

    async def write_screenshot(*, path: Path) -> None:
        path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture

    page.goto = AsyncMock()
    page.screenshot = AsyncMock(side_effect=write_screenshot)
    page.close = AsyncMock(side_effect=RuntimeError('page close failed'))
    context = MagicMock()
    context.new_page = AsyncMock(return_value=page)
    context.close = AsyncMock()
    browser = MagicMock()
    browser.new_context = AsyncMock(return_value=context)
    browser.close = AsyncMock()
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)

    async def reachable_targets(_self, targets: list[str]) -> list[tuple[str, str]]:
        return [(targets[0], f'https://{targets[0]}')]

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module.ScreenShotter, 'reachable_targets', reachable_targets)

    result = await theharvester_main.start(
        EnumerationOptions(domain='api.example.test', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'failed'
    assert execution.stop_reason == 'capture-errors'
    assert execution.error_type == 'RuntimeError'
    page.close.assert_awaited_once()
    context.close.assert_awaited_once()
    browser.close.assert_awaited_once()
    manager.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_cli_can_capture_an_explicit_target_without_discovery_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []
    saved: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            saved.append(result)

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return host, 'https'

        async def take_screenshot(self, host: str, *, output_path: Path | None = None) -> str:
            captured.append(host)
            (output_path or self.screenshot_path(host)).write_bytes(b'png')
            return f'https://{host}'

        def screenshot_path(self, host: str) -> Path:
            return Path(self.output) / f'{host.removeprefix("https://")}.png'

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'api.example.com', '--screenshot', str(tmp_path), '--quiet'],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured == ['api.example.com']
    completed = saved[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'completed'
    assert execution.result_count == 0
    assert ('screenshot', 'https://api.example.com') not in completed.results
    assert ('hostname', 'api.example.com') in completed.results
    assert len(execution.artifacts) == 1
    artifact = execution.artifacts[0]
    assert artifact.subject_value == 'api.example.com'
    assert artifact.path == f'{tmp_path.name}/api.example.com.png'
    assert artifact.media_type == 'image/png'
    assert artifact.size_bytes == 3


@pytest.mark.asyncio
async def test_screenshot_reports_no_reachable_target_as_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, _host: str) -> tuple[str, str]:
            return '', ''

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(domain='api.example.test', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'failed'
    assert execution.stop_reason == 'no-reachable-targets'


@pytest.mark.asyncio
async def test_screenshot_redirect_stays_attached_to_the_authorized_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            assert host == 'api.example.test'
            return 'https://outside.example/path', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            (output_path or self.screenshot_path(url)).write_bytes(b'png')
            return url

        def screenshot_path(self, _url: str) -> Path:
            return Path(self.output) / 'outside.example.png'

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(domain='api.example.test', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'screenshot')
    assert execution.artifacts[0].subject_value == 'api.example.test'
    assert ('hostname', 'outside.example') not in completed.results


@pytest.mark.asyncio
async def test_target_only_ip_screenshot_keeps_ip_result_and_artifact_subject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            assert output_path is not None
            output_path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory screenshot fixture
            return url

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(domain='192.0.2.1', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    execution = next(item for item in completed.active_evidence.executions if item.action == 'screenshot')
    assert ('ip', '192.0.2.1') in completed.results
    assert ('hostname', '192.0.2.1') not in completed.results
    assert execution.artifacts[0].subject_kind == 'ip'
    assert execution.artifacts[0].subject_value == '192.0.2.1'


@pytest.mark.asyncio
async def test_screenshot_redirects_to_one_login_keep_distinct_subject_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, _host: str) -> tuple[str, str]:
            return 'https://login.example.net/session', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            assert url == 'https://login.example.net/session'
            assert output_path is not None
            output_path.write_bytes(output_path.name.encode())  # noqa: ASYNC240 - tiny in-memory screenshot fixture
            return url

        def screenshot_path(self, url: str) -> Path:
            hostname = url.removeprefix('https://').split('/', maxsplit=1)[0]
            return Path(self.output) / f'{hostname}.png'

    class TwoHostSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'first.example.test', 'second.example.test'}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', TwoHostSource)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(
            domain='example.test',
            screenshot=str(tmp_path),
            quiet=True,
            source='crtsh',
        ),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'screenshot')
    assert [(artifact.subject_value, Path(artifact.path).name) for artifact in execution.artifacts] == [
        ('first.example.test', 'first.example.test.png'),
        ('second.example.test', 'second.example.test.png'),
    ]


@pytest.mark.asyncio
async def test_screenshot_cancellation_persists_failed_execution_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    saved: list[CompletedResult] = []
    captured = asyncio.Event()

    class RecordingResultStore(_NoopResultStore):
        async def save_run(self, result: CompletedResult) -> None:
            saved.append(result)

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        async def take_screenshot(self, host: str, *, output_path: Path | None = None) -> str:
            if 'first.' in host:
                (output_path or self.screenshot_path(host)).write_bytes(b'png')
                captured.set()
                return host
            await asyncio.Event().wait()
            return ''

        def screenshot_path(self, host: str) -> Path:
            return Path(self.output) / f'{host.removeprefix("https://")}.png'

    class TwoHostSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'first.example.test', 'second.example.test'}

    monkeypatch.setattr(theharvester_main, 'ResultStore', RecordingResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', TwoHostSource)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    task = asyncio.create_task(
        theharvester_main.start(
            EnumerationOptions(
                domain='example.test',
                screenshot=str(tmp_path),
                quiet=True,
                source='crtsh',
            ),
            return_completed_result=True,
        )
    )
    await captured.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'partial'
    assert execution.stop_reason == 'cancelled'
    assert [artifact.subject_value for artifact in execution.artifacts] == ['first.example.test']


@pytest.mark.asyncio
async def test_screenshot_capture_failure_cancels_sibling_tasks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sibling_cancelled = asyncio.Event()

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            if 'first.' in url:
                raise RuntimeError('capture failed')
            try:
                await asyncio.Event().wait()
            finally:
                sibling_cancelled.set()
            return ''

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

    class TwoHostSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'first.example.test', 'second.example.test'}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', TwoHostSource)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)

    result = await theharvester_main.start(
        EnumerationOptions(
            domain='example.test',
            screenshot=str(tmp_path),
            quiet=True,
            source='crtsh',
        ),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'screenshot')
    assert execution.status == 'failed'
    assert sibling_cancelled.is_set()


@pytest.mark.asyncio
async def test_direct_action_evidence_reaches_completed_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from theHarvester.lib.shodan_evidence import ShodanHostObservation

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
        def __init__(self, hosts: list[str], *, target: str, nameservers: list[str]) -> None:
            assert hosts == ['api.example.com']
            assert target == 'example.com'
            assert nameservers == ['192.0.2.53']
            self.request_count = 2
            self.request_error_count = 0
            self.dns_error_count = 0
            self.completed_count = 1
            self.request_error_types: set[str] = set()
            self.scan_error_type = None
            self.stop_reason = None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is True

        async def get_takeover_outcomes(self) -> tuple[TakeoverCandidateOutcome, ...]:
            return (_takeover_outcome(),)

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return host, 'reachable'

        async def take_screenshot(self, host: str, *, output_path: Path | None = None) -> str:
            (output_path or self.screenshot_path(host)).write_bytes(b'png')
            return f'https://{host}'

        def screenshot_path(self, host: str) -> Path:
            return Path(self.output) / f'{host.removeprefix("https://")}.png'

    class FakeShodan:
        error_type = None

        def __init__(self) -> None:
            self.attributions: set[AsnAttributionObservation] = set()
            self.hosts: dict[str, ShodanHostObservation] = {}

        async def search_ip(self, ip: str, *, proxy: bool = False) -> dict[str, dict[str, object]]:
            assert proxy is True
            self.attributions.add(
                AsnAttributionObservation(
                    'action',
                    'shodan',
                    'AS64496',
                    'Example Transit',
                    'ip',
                    ip,
                    datetime.now(UTC),
                )
            )
            self.hosts[ip] = ShodanHostObservation.from_record(
                ip,
                {
                    'asn': 'AS64496',
                    'organization': 'Example Transit',
                    'services': [{'port': 443, 'transport': 'tcp', 'product': 'nginx'}],
                },
            )
            return {ip: self.hosts[ip].to_details()}

        async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
            return self.attributions

        async def get_shodan_hosts(self) -> tuple[ShodanHostObservation, ...]:
            return tuple(self.hosts.values())

    class FakeApiScanner:
        def __init__(self, word: str, wordlist: str, exact_paths: bool = False) -> None:
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

    async def no_sleep(_seconds: float) -> None:
        return None

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api/v1\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeoverScanner', FakeTakeOver)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
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
    assert ('url', 'https://example.com/api/v1') in completed.results
    assert ('screenshot', 'api.example.com') not in completed.results
    assert ('shodan-host', '192.0.2.10') in completed.results
    assert completed.shodan_hosts[0].to_details() == {
        'asn': 'AS64496',
        'organization': 'Example Transit',
        'services': [{'port': 443, 'transport': 'tcp', 'product': 'nginx'}],
    }
    assert ('asn', 'AS64496') in completed.results
    assert completed.asn_attributions[0].organization_label == 'Example Transit'
    takeover_result = (
        'takeover',
        'api.example.com',
    )
    assert takeover_result in completed.results
    assert completed.takeover_outcomes == (_takeover_outcome(),)
    takeover_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'takeover')
    assert takeover_execution.status == 'completed'
    assert takeover_execution.result_count == 1
    assert takeover_execution.error_type is None
    assert takeover_execution.stop_reason is None
    screenshot_execution = next(
        execution for execution in completed.active_evidence.executions if execution.action == 'screenshot'
    )
    assert screenshot_execution.status == 'completed'
    assert screenshot_execution.result_count == 0
    assert screenshot_execution.artifacts[0].subject_value == 'api.example.com'
    shodan_execution = next(execution for execution in completed.active_evidence.executions if execution.action == 'shodan')
    assert shodan_execution.status == 'completed'
    assert shodan_execution.result_count == 3
    assert shodan_execution.error_type is None
    assert shodan_execution.stop_reason is None
    api_executions = [execution for execution in completed.active_evidence.executions if execution.action == 'api-scan']
    assert len(api_executions) == 1
    api_execution = api_executions[0]
    assert api_execution.status == 'completed'
    assert api_execution.result_count == 1
    assert api_execution.error_type is None
    assert api_execution.stop_reason is None
    assert {(observation.kind, observation.value) for observation in api_execution.observations} == {
        ('url', 'https://example.com/api/v1')
    }


@pytest.mark.asyncio
async def test_shodan_source_evidence_is_not_overwritten_by_conflicting_action_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from theHarvester.lib.shodan_evidence import ShodanHostObservation

    class ConflictingShodan:
        error_type = None

        def __init__(self, word: str | None = None) -> None:
            self.word = word
            self.host = (
                ShodanHostObservation.from_record(
                    '192.0.2.10',
                    {'services': [{'port': 53, 'transport': 'udp'}]},
                )
                if word is not None
                else None
            )

        async def process(self, proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'} if self.word is not None else set()

        async def search_ip(self, ip: str, *, proxy: bool = False) -> dict[str, dict[str, object]]:
            self.host = ShodanHostObservation.from_record(
                ip,
                {'services': [{'port': 443, 'transport': 'tcp'}]},
            )
            return {ip: self.host.to_details()}

        async def get_shodan_hosts(self) -> tuple[ShodanHostObservation, ...]:
            return (self.host,) if self.host is not None else ()

        async def get_asn_attributions(self) -> set:
            if self.word is not None:
                return set()
            return {
                AsnAttributionObservation(
                    'action',
                    'shodan',
                    'AS64496',
                    'Example Transit',
                    'ip',
                    '192.0.2.10',
                    datetime.now(UTC),
                )
            }

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', ConflictingShodan)

    result = await theharvester_main.start(
        EnumerationOptions(
            dns_resolve='192.0.2.53',
            domain='example.com',
            quiet=True,
            shodan=True,
            source='shodan',
        ),
        return_completed_result=True,
    )

    completed = result[-1]
    assert completed.shodan_hosts[0].to_details() == {'services': [{'port': 53, 'transport': 'udp'}]}
    assert ResultObservation('shodan', 'shodan-host', '192.0.2.10') in completed.observations
    execution = next(item for item in completed.active_evidence.executions if item.action == 'shodan')
    assert execution.status == 'partial'
    assert execution.error_type == 'ValueError'
    assert {(observation.kind, observation.value) for observation in execution.observations} == {
        ('asn', 'AS64496'),
        ('ip', '192.0.2.10'),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        'request_count',
        'request_errors',
        'scan_error',
        'inconclusive_count',
        'expected_status',
        'expected_error',
        'expected_reason',
    ),
    [
        (2, 1, None, 0, 'partial', 'TransportError', 'request-errors'),
        (2, 2, None, 1, 'failed', 'TransportError', 'incomplete-candidates'),
        (0, 0, 'RuntimeError', 0, 'failed', 'RuntimeError', 'scan-error'),
        (0, 0, None, 1, 'failed', 'WildcardIndistinguishableError', 'wildcard-indistinguishable'),
    ],
)
async def test_takeover_action_records_suppressed_outcome(
    monkeypatch: pytest.MonkeyPatch,
    request_count: int,
    request_errors: int,
    scan_error: str | None,
    inconclusive_count: int,
    expected_status: str,
    expected_error: str | None,
    expected_reason: str,
) -> None:
    class FakeTakeOver:
        def __init__(self, _hosts: list[str], **_kwargs: object) -> None:
            self.request_count = request_count
            self.request_error_count = request_errors
            self.dns_error_count = 0
            self.inconclusive_count = inconclusive_count
            self.candidate_count = 1
            self.completed_count = 0 if scan_error else 1
            self.request_error_types = (
                {'TransportError'} if request_errors else {'WildcardIndistinguishableError'} if inconclusive_count else set()
            )
            self.scan_error_type = scan_error
            if scan_error:
                self.stop_reason = 'scan-error'
            elif inconclusive_count:
                self.stop_reason = 'incomplete-candidates' if request_errors else 'wildcard-indistinguishable'
            else:
                self.stop_reason = None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            return None

        async def get_takeover_outcomes(self) -> tuple[TakeoverCandidateOutcome, ...]:
            if scan_error:
                return ()
            if inconclusive_count:
                return (
                    TakeoverCandidateOutcome.from_record(
                        'api.example.com',
                        {
                            'status': 'inconclusive',
                            'dns': [
                                {
                                    'resolver': '1.1.1.1',
                                    'cname_chain': ['missing-bucket.s3.amazonaws.com'],
                                    'terminal_rcode': 'NOERROR',
                                }
                            ],
                            'wildcard_dns': [
                                {
                                    'resolver': '1.1.1.1',
                                    'cname_chain': [],
                                    'terminal_rcode': 'NXDOMAIN',
                                }
                            ],
                            'http': [],
                            'indicators': [],
                            'error_types': ['TransportError'] if request_errors else ['WildcardIndistinguishableError'],
                        },
                    ),
                )
            return (_takeover_outcome(),)

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeoverScanner', FakeTakeOver)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', quiet=True, source='crtsh', take_over=True),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'takeover')
    assert execution.status == expected_status
    assert execution.result_count == (0 if scan_error else 1)
    assert execution.error_type == expected_error
    assert execution.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_shodan_action_records_all_target_errors_as_failed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    class FailedShodan:
        error_type = None

        async def search_ip(self, ip: str, *, proxy: bool = False) -> dict[str, str]:
            assert proxy is False
            raise RuntimeError(f'provider-secret-payload for {ip}')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FailedShodan)

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

        async def search_ip(self, _ip: str, *, proxy: bool = False) -> dict:
            assert proxy is False
            return {}

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', _ApiHostChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', EmptyShodan)

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
    (
        'scan_error',
        'request_errors',
        'rate_limited',
        'scanner_reason',
        'result_url',
        'expected_status',
        'expected_error',
        'expected_reason',
    ),
    [
        ('RuntimeError', 0, False, None, None, 'failed', 'RuntimeError', 'scan-error'),
        (None, 3, False, None, None, 'partial', 'TransportError', 'request-errors'),
        (None, 0, True, None, None, 'rate-limited', None, 'rate-limited'),
        (None, 0, False, 'request-limit', None, 'failed', None, 'request-limit'),
        (None, 1, False, None, 'https://example.com/api', 'partial', 'ResponseLimitError', 'request-errors'),
    ],
)
async def test_api_scan_records_suppressed_scan_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scan_error: str | None,
    request_errors: int,
    rate_limited: bool,
    scanner_reason: str | None,
    result_url: str | None,
    expected_status: str,
    expected_error: str | None,
    expected_reason: str,
) -> None:
    class FailedApiScanner:
        scan_error_type = scan_error
        request_error_count = request_errors
        request_error_types = {'ResponseLimitError' if result_url else 'TransportError'} if request_errors else set()
        stop_reason = scanner_reason

        def __init__(self, word: str, wordlist: str, exact_paths: bool = False) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')
            assert exact_paths is True

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> dict:
            return {result_url: object()} if result_url else {}

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
    assert api_execution.result_count == int(result_url is not None)
    assert api_execution.error_type == expected_error
    assert api_execution.stop_reason == expected_reason


@pytest.mark.asyncio
async def test_api_scan_logs_result_collections_deterministically(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    def unordered_values(prefix: str) -> set[str]:
        for index in range(100):
            values = {f'{prefix}-a-{index}', f'{prefix}-z-{index}'}
            if list(values) != sorted(values):
                return values
        raise AssertionError('could not construct an unordered set fixture')

    endpoint_values = unordered_values('https://example.com/api')
    method_values = unordered_values('METHOD')

    class FakeApiScanner:
        scan_error_type = None
        request_error_count = 0
        stop_reason = None

        def __init__(self, word: str, wordlist: str, exact_paths: bool = False) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')
            assert exact_paths is True
            self.request_error_types: set[str] = set()

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> set[str]:
            return endpoint_values

        def get_interesting_endpoints(self) -> set[str]:
            return set()

        def get_auth_required(self) -> set[str]:
            return set()

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict[str, object]:
            return {}

        def get_methods(self) -> set[str]:
            return method_values

        def get_status_codes(self) -> set[int]:
            return {200}

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    caplog.set_level(logging.INFO, logger='theHarvester.output')

    await theharvester_main.start(
        EnumerationOptions(api_scan=True, domain='example.com', quiet=True, wordlist=str(wordlist)),
        return_completed_result=True,
    )

    rendered_endpoints = [
        message.removeprefix('    - ') for message in caplog.messages if message.startswith('    - https://example.com/api')
    ]
    assert rendered_endpoints == sorted(endpoint_values)
    assert f'[*] HTTP methods used: {", ".join(sorted(method_values))}' in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('limited_status', 'expected_status', 'expected_error', 'expected_reason'),
    [
        (429, 'rate-limited', None, 'rate-limited'),
        (503, 'partial', 'HTTP503Error', 'request-errors'),
    ],
)
async def test_api_scan_reports_exhausted_retries_truthfully(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    limited_status: int,
    expected_status: str,
    expected_error: str | None,
    expected_reason: str,
) -> None:
    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')

    async def detect_schema(self, _path: str = '') -> str:
        return 'https'

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        return FetcherResponse(body='unavailable', status=limited_status, headers={'retry-after': '0'})

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.api_endpoints.SearchApiEndpoints, '_detect_schema', detect_schema)
    monkeypatch.setattr(theharvester_main.api_endpoints.AsyncFetcher, 'fetch', fetch)
    monkeypatch.setattr(theharvester_main.api_endpoints.asyncio, 'sleep', no_sleep)
    caplog.set_level(logging.INFO, logger='theHarvester.output')

    result = await theharvester_main.start(
        EnumerationOptions(api_scan=True, domain='example.com', quiet=True, wordlist=str(wordlist)),
        return_completed_result=True,
    )

    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'api-scan')
    assert execution.status == expected_status
    assert execution.result_count == 1
    assert execution.error_type == expected_error
    assert execution.stop_reason == expected_reason
    assert 'API scanning completed successfully.' not in caplog.text
    assert f'API scanning stopped with reason: {expected_reason}.' in caplog.text


@pytest.mark.asyncio
async def test_takeover_without_hosts_is_skipped_without_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnexpectedTakeOver:
        def __init__(self, _hosts: list[str], **_kwargs: object) -> None:
            raise AssertionError('takeover should not start without hosts')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeoverScanner', UnexpectedTakeOver)

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
async def test_routeviews_persists_typed_network_evidence_for_explicit_ip_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], tuple[str, ...], str | None]] = []

    async def fake_routeviews(asns, network_seeds, *, api_key: str | None = None) -> RouteViewsResult:
        calls.append((tuple(asns), tuple(network_seeds), api_key))
        collected_at = datetime.now(UTC)
        origin = PrefixOriginObservation('routeviews', '192.0.2.0/24', 'AS64500', collected_at)
        rpki = RpkiValidationObservation(
            'routeviews',
            '192.0.2.0/24',
            'AS64500',
            'valid',
            collected_at,
            collected_at,
        )
        return RouteViewsResult(
            prefixes=('192.0.2.0/24',),
            origin_asns=('AS64500',),
            observations=(origin, rpki),
            request_count=1,
            error_count=0,
            status='completed',
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'enrich_routeviews', fake_routeviews)
    monkeypatch.setattr(theharvester_main.Core, 'routeviews_key', staticmethod(lambda: 'routeviews-key'))

    result = await theharvester_main.start(
        EnumerationOptions(domain='192.0.2.7', quiet=True, routeviews=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert calls == [((), ('192.0.2.7',), 'routeviews-key')]
    assert {value for kind, value in completed.results if kind == 'prefix'} == {'192.0.2.0/24'}
    assert {value for kind, value in completed.results if kind == 'asn'} == {'AS64500'}
    assert len(completed.network_observations) == 2
    assert isinstance(completed.network_observations[0], PrefixOriginObservation)
    assert isinstance(completed.network_observations[1], RpkiValidationObservation)
    execution = next(item for item in completed.active_evidence.executions if item.action == 'routeviews')
    assert execution.status == 'completed'
    assert {(item.kind, item.value) for item in execution.observations} == {
        ('asn', 'AS64500'),
        ('prefix', '192.0.2.0/24'),
    }


@pytest.mark.asyncio
async def test_routeviews_pivots_from_an_explicit_asn_target(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[object, ...], tuple[str, ...]]] = []

    async def fake_routeviews(asns, network_seeds, *, api_key: str | None = None) -> RouteViewsResult:
        assert api_key is None
        calls.append((tuple(asns), tuple(network_seeds)))
        return RouteViewsResult((), (), (), 2, 0, 'completed', stop_reason='no-results')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(theharvester_main, 'enrich_routeviews', fake_routeviews)
    monkeypatch.setattr(theharvester_main.Core, 'routeviews_key', staticmethod(lambda: None))

    result = await theharvester_main.start(
        EnumerationOptions(domain='as64500', quiet=True, routeviews=True),
        return_completed_result=True,
    )

    assert calls == [(('AS64500',), ())]
    assert result[-1].target == 'AS64500'
    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'routeviews')
    assert execution.status == 'completed'
    assert execution.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_explicit_asn_target_rejects_discovery_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)

    with pytest.raises(ValueError, match='ASN target requires --routeviews without discovery sources or other actions'):
        await theharvester_main.start(
            EnumerationOptions(domain='AS64500', quiet=True, routeviews=True, source='crtsh'),
            return_completed_result=True,
        )


@pytest.mark.asyncio
async def test_routeviews_hostname_target_requires_a_discovery_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)

    with pytest.raises(ValueError, match='RouteViews hostname target requires a discovery source'):
        await theharvester_main.start(
            EnumerationOptions(domain='api.example.com', quiet=True, routeviews=True),
            return_completed_result=True,
        )


@pytest.mark.asyncio
async def test_routeviews_pivots_from_attributed_ips_without_expanding_discovered_asns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], tuple[str, ...]]] = []

    class FakeUrlscan:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            raise AssertionError('hostname results must not be retrieved')

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

        async def get_asns(self) -> set[str]:
            return {'AS64500'}

        async def get_urls(self) -> set[str]:
            return set()

        async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
            return {
                AsnAttributionObservation(
                    'source',
                    'urlscan',
                    'AS64500',
                    'Example Transit',
                    'ip',
                    '192.0.2.10',
                    datetime.now(UTC),
                ),
                AsnAttributionObservation(
                    'source',
                    'urlscan',
                    'AS64500',
                    'Example Transit',
                    'hostname',
                    'example.com',
                    datetime.now(UTC),
                ),
            }

    async def fake_routeviews(asns, network_seeds, *, api_key: str | None = None) -> RouteViewsResult:
        assert api_key is None
        calls.append((tuple(asns), tuple(network_seeds)))
        return RouteViewsResult((), (), (), 2, 0, 'completed', stop_reason='no-results')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _NoopResultStore)
    monkeypatch.setattr(source_runner.urlscan, 'SearchUrlscan', FakeUrlscan)
    monkeypatch.setattr(theharvester_main, 'enrich_routeviews', fake_routeviews)
    monkeypatch.setattr(theharvester_main.Core, 'routeviews_key', staticmethod(lambda: None))

    result = await theharvester_main.start(
        EnumerationOptions(
            domain='example.com',
            quiet=True,
            routeviews=True,
            source='urlscan',
            proxies=True,
            no_hosts=True,
        ),
        return_completed_result=True,
    )

    assert calls == [((), ('192.0.2.10',))]
    completed = result[-1]
    assert ('asn', 'AS64500') in completed.results
    assert ('ip', '192.0.2.10') in completed.results
    assert not any(kind == 'hostname' for kind, _value in completed.results)
    assert len(completed.asn_attributions) == 1
    assert completed.asn_attributions[0].subject_value == '192.0.2.10'
    execution = next(item for item in result[-1].active_evidence.executions if item.action == 'routeviews')
    assert execution.status == 'completed'
    assert execution.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_routeviews_cancellation_persists_partial_network_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    saved: list[CompletedResult] = []

    async def cancel_routeviews(asns, network_seeds, *, api_key: str | None = None) -> RouteViewsResult:
        assert tuple(asns) == ()
        assert tuple(network_seeds) == ('192.0.2.7',)
        assert api_key is None
        collected_at = datetime.now(UTC)
        origin = PrefixOriginObservation('routeviews', '192.0.2.0/24', 'AS64500', collected_at)
        raise RouteViewsCancelled(
            RouteViewsResult(
                prefixes=('192.0.2.0/24',),
                origin_asns=('AS64500',),
                observations=(origin,),
                request_count=1,
                error_count=1,
                status='partial',
                error_type='CancelledError',
                stop_reason='cancelled',
            )
        )

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'enrich_routeviews', cancel_routeviews)
    monkeypatch.setattr(theharvester_main.Core, 'routeviews_key', staticmethod(lambda: None))

    with pytest.raises(RouteViewsCancelled):
        await theharvester_main.start(
            EnumerationOptions(domain='192.0.2.7', quiet=True, routeviews=True),
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'routeviews')
    assert execution.status == 'partial'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert ('prefix', '192.0.2.0/24') in saved[-1].results


@pytest.mark.asyncio
async def test_routeviews_cancellation_persists_when_the_checkpoint_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    saved: list[CompletedResult] = []

    async def cancel_routeviews(asns, network_seeds, *, api_key: str | None = None) -> RouteViewsResult:
        assert api_key is None
        collected_at = datetime.now(UTC)
        origin = PrefixOriginObservation('routeviews', '192.0.2.0/24', 'AS64500', collected_at)
        raise RouteViewsCancelled(
            RouteViewsResult(
                prefixes=('192.0.2.0/24',),
                origin_asns=('AS64500',),
                observations=(origin,),
                request_count=1,
                error_count=1,
                status='partial',
                error_type='CancelledError',
                stop_reason='cancelled',
            )
        )

    async def failed_checkpoint(result: CompletedResult) -> None:
        if any(execution.action == 'routeviews' for execution in result.active_evidence.executions):
            raise RuntimeError('checkpoint failed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(theharvester_main, 'enrich_routeviews', cancel_routeviews)
    monkeypatch.setattr(theharvester_main.Core, 'routeviews_key', staticmethod(lambda: None))

    with pytest.raises(RouteViewsCancelled):
        await theharvester_main.start(
            EnumerationOptions(domain='192.0.2.7', quiet=True, routeviews=True),
            completed_result_checkpoint=failed_checkpoint,
            return_completed_result=True,
        )

    execution = next(item for item in saved[-1].active_evidence.executions if item.action == 'routeviews')
    assert execution.stop_reason == 'cancelled'
    assert ('prefix', '192.0.2.0/24') in saved[-1].results


@pytest.mark.asyncio
async def test_api_scan_cancellation_persists_failure_and_propagates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    saved: list[CompletedResult] = []

    class CancelledApiScanner:
        def __init__(self, word: str, wordlist: str, exact_paths: bool = False) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')
            assert exact_paths is True

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
    assert execution.result_count == 1
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'
    assert {(observation.kind, observation.value) for observation in execution.observations} == {
        ('url', 'https://example.com/api/v1')
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('raised_error', 'failure_stage', 'expected_status', 'expected_count'),
    [
        (RuntimeError('scan failed'), 'search', 'partial', 1),
        (MissingKey('API endpoints'), 'init', 'failed', 0),
        (RuntimeError('getter failed'), 'getter', 'partial', 1),
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
        def __init__(self, word: str, wordlist: str, exact_paths: bool = False) -> None:
            assert exact_paths is True
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
            ('url', 'https://example.com/api/v1')
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
        def __init__(self, _hosts: list[str], **_kwargs: object) -> None:
            self.request_count = 0
            self.request_error_count = 0
            self.dns_error_count = 0
            self.completed_count = 0
            self.request_error_types: set[str] = set()
            self.scan_error_type = None
            self.stop_reason = None
            if failure_stage == 'init':
                raise raised_error

        async def process(self, _proxy: bool = False, **_kwargs) -> None:
            if failure_stage == 'process':
                raise raised_error

        async def get_takeover_outcomes(self) -> tuple[TakeoverCandidateOutcome, ...]:
            if failure_stage == 'getter':
                raise raised_error
            return ()

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeoverScanner', CancelledTakeOver)

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
    from theHarvester.lib.shodan_evidence import ShodanHostObservation

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

        def __init__(self) -> None:
            self.calls = 0
            self.hosts: dict[str, ShodanHostObservation] = {}

        async def search_ip(self, ip: str, *, proxy: bool = False) -> dict:
            assert proxy is False
            self.calls += 1
            if self.calls == 2:
                raise asyncio.CancelledError
            self.hosts[ip] = ShodanHostObservation.from_record(
                ip,
                {'services': [{'port': 443, 'transport': 'tcp'}]},
            )
            return {ip: self.hosts[ip].to_details()}

        async def get_shodan_hosts(self) -> tuple[ShodanHostObservation, ...]:
            return tuple(self.hosts.values())

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', CancelledShodan)

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
    from theHarvester.lib.shodan_evidence import ShodanHostObservation

    checkpoints: list[CompletedResult] = []
    saved: list[CompletedResult] = []

    class FakeTakeOver:
        def __init__(self, _hosts: list[str], **_kwargs: object) -> None:
            self.request_count = 1
            self.request_error_count = 0
            self.dns_error_count = 0
            self.completed_count = 1
            self.request_error_types: set[str] = set()
            self.scan_error_type = None
            self.stop_reason = None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False

        async def get_takeover_outcomes(self) -> tuple[TakeoverCandidateOutcome, ...]:
            return ()

    class FakeShodan:
        error_type = None

        def __init__(self) -> None:
            self.hosts: dict[str, ShodanHostObservation] = {}

        async def search_ip(self, ip: str, *, proxy: bool = False) -> dict:
            assert proxy is False
            self.hosts[ip] = ShodanHostObservation.from_record(
                ip,
                {'services': [{'port': 443, 'transport': 'tcp'}]},
            )
            return {ip: self.hosts[ip].to_details()}

        async def get_shodan_hosts(self) -> tuple[ShodanHostObservation, ...]:
            return tuple(self.hosts.values())

    async def cancel_after_action(result: CompletedResult) -> None:
        if any(execution.action == action for execution in result.active_evidence.executions):
            checkpoints.append(result)
            raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main, 'ResultStore', _recording_result_store(saved))
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', _ApiHostSource)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeoverScanner', FakeTakeOver)
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
    assert saved[-1] == checkpoints[-1]


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
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeCrtsh)
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
    assert captured == [('example.com', ('api.example.com',), 1, None)]
    assert sorted(closed) == ['192.0.2.53', '192.0.2.54', '192.0.2.55']
    assert completed
    assert ('hostname', 'dev.api.example.com') in completed[0].results
    assert ('ip', '192.0.2.2') in completed[0].results
    assert ('ip', '2001:db8::2') in completed[0].results
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
        ('ip', '192.0.2.2'),
        ('ip', '2001:db8::2'),
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
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', FakeCrtsh)
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
