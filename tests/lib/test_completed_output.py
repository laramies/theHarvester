from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import ClassVar
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient

from theHarvester.lib.dns_validation import DnsResponse, DnsValidator
from theHarvester.lib.output import (
    evidence_xml_fragment,
    format_run_terminal,
    legacy_json_result,
    run_result_jsonl,
)
from theHarvester.lib.run import (
    Derivation,
    RunStatus,
    SourceFinding,
    SourceRateLimitedError,
    SourceStatus,
    SQLiteRunStore,
    StageFinding,
    StageFindingKind,
    StageResult,
    complete_run,
    execute_run,
)


class CompletedRunSource:
    name = 'fixture'
    family = 'fixture-family'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [
            SourceFinding(
                'api.example.com',
                observed_at=datetime(2026, 7, 15, 12, tzinfo=UTC),
            ),
            SourceFinding('old.example.com'),
        ]


class IncompleteRunSource:
    name = 'fixture'
    family = 'fixture-family'

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def collect(self, _target: str) -> list[SourceFinding]:
        raise self.error


@pytest.mark.asyncio
async def test_completed_run_serializes_status_and_meaningful_timestamps() -> None:
    result = await execute_run('example.com', (CompletedRunSource(),))

    serialized = result.to_dict()

    assert result.status is RunStatus.COMPLETE
    assert serialized['started_at']
    assert serialized['completed_at']
    assert serialized['observations'][0]['collected_at']
    assert serialized['observations'][0]['provider_observed_at'] == '2026-07-15T12:00:00+00:00'
    assert 'provider_observed_at' not in serialized['observations'][1]


@pytest.mark.asyncio
async def test_complete_run_merges_late_and_direct_stage_results() -> None:
    result = await execute_run('example.com', (CompletedRunSource(),))
    dns_completed_at = datetime(2026, 7, 15, 13, tzinfo=UTC)
    direct_completed_at = datetime(2026, 7, 15, 14, tzinfo=UTC)

    completed = complete_run(
        result,
        (
            StageResult(
                'action:dns-brute',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.HOSTNAME, 'late.example.com:192.0.2.11'),),
                is_action=True,
                completed_at=dns_completed_at,
            ),
            StageResult(
                'action:take-over',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.TAKEOVER, 'api.example.com', 'not vulnerable'),),
                is_action=True,
                completed_at=direct_completed_at,
            ),
        ),
    )

    assert {entity.value for entity in completed.entities} == {
        'api.example.com',
        'old.example.com',
        'late.example.com',
    }
    assert {(item.kind, item.value, item.detail) for item in completed.selected_observations} == {
        (StageFindingKind.TAKEOVER, 'api.example.com', 'not vulnerable')
    }
    assert {execution.source for execution in completed.source_executions} == {'fixture'}
    assert {execution.stage for execution in completed.stage_executions} == {
        'action:dns-brute',
        'action:take-over',
    }
    assert next(item for item in completed.observations if item.value == 'late.example.com').collected_at == dns_completed_at
    assert completed.selected_observations[0].collected_at == direct_completed_at


class TerminalRunSource:
    name = 'fixture'
    family = 'fixture-family'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [
            SourceFinding('api.example.com'),
            SourceFinding('old.example.com'),
            SourceFinding('related.example.net', Derivation.SCOPE_EXTENSION),
            SourceFinding('cdn.vendor.test', Derivation.EXTERNAL_RELATIONSHIP),
        ]


class TerminalResolver:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, hostname: str) -> DnsResponse:
        if hostname == 'api.example.com':
            return DnsResponse(ipv4=('192.0.2.10',))
        return DnsResponse(rcode='NXDOMAIN')


@pytest.mark.asyncio
async def test_terminal_reports_each_hostname_once_with_status_and_sources() -> None:
    validator = DnsValidator(tuple(TerminalResolver(f'resolver-{index}') for index in range(3)))
    result = await execute_run('example.com', (TerminalRunSource(),), dns_validator=validator)
    result = complete_run(
        result,
        (
            StageResult(
                'action:take-over',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.TAKEOVER, 'api.example.com', 'not vulnerable'),),
                is_action=True,
            ),
        ),
    )

    terminal = format_run_terminal(result)

    for hostname in ('api.example.com', 'old.example.com', 'related.example.net', 'cdn.vendor.test'):
        assert terminal.count(hostname) == 1
    assert 'Currently addressable subdomains (1)' in terminal
    assert 'Secondary evidence / needs review (2)' in terminal
    assert 'Scope-extension candidates (1)' in terminal
    assert 'status=currently-addressable; sources=fixture; takeover=not vulnerable' in terminal
    assert 'related.example.net [status=scope-extension-candidate; sources=fixture]' in terminal
    assert 'cdn.vendor.test [status=external-relationship; sources=fixture]' in terminal
    assert 'status=None' not in terminal
    assert 'Run status: complete' in terminal


@pytest.mark.asyncio
async def test_terminal_keeps_recognizable_non_host_sections() -> None:
    result = await execute_run('example.com', (CompletedRunSource(),))
    result = complete_run(
        result,
        (
            StageResult(
                'fixture',
                SourceStatus.SUCCEEDED,
                1,
                5,
                (
                    StageFinding(StageFindingKind.EMAIL, 'ops@example.com'),
                    StageFinding(StageFindingKind.IP_ADDRESS, '192.0.2.10'),
                    StageFinding(StageFindingKind.ASN, 'AS64500'),
                    StageFinding(StageFindingKind.PERSON, 'Alice'),
                    StageFinding(StageFindingKind.INTERESTING_URL, 'https://example.com/status'),
                ),
            ),
        ),
    )

    terminal = format_run_terminal(result)

    assert '[*] Emails found: 1' in terminal
    assert '[*] IPs found: 1' in terminal
    assert '[*] ASNS found: 1' in terminal
    assert '[*] People found: 1' in terminal
    assert '[*] Interesting Urls found: 1' in terminal
    assert 'ops@example.com [status=observed; sources=fixture]' in terminal


@pytest.mark.asyncio
async def test_jsonl_preserves_typed_records_provenance_and_timestamps() -> None:
    validator = DnsValidator(tuple(TerminalResolver(f'resolver-{index}') for index in range(3)))
    result = await execute_run('example.com', (CompletedRunSource(),), dns_validator=validator)

    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]

    assert {record['record_type'] for record in records} == {
        'run',
        'source_execution',
        'discovery_observation',
        'dns_validation_observation',
        'merged_result',
    }
    assert all(record['schema_version'] == 'theharvester-evidence-v1' for record in records)
    assert all(record['run_id'] == result.run_id for record in records)
    discovery = [record['data'] for record in records if record['record_type'] == 'discovery_observation']
    assert all(record['collected_at'] for record in discovery)
    assert discovery[0]['provider_observed_at'] == '2026-07-15T12:00:00+00:00'
    assert 'provider_observed_at' not in discovery[1]
    validations = [record['data'] for record in records if record['record_type'] == 'dns_validation_observation']
    assert all(record['validated_at'] for record in validations)
    assert all('queried_at' not in record for record in validations)
    merged = [record['data'] for record in records if record['record_type'] == 'merged_result']
    assert all(record['provenance'] for record in merged)


@pytest.mark.asyncio
async def test_legacy_json_and_xml_keep_existing_fields_and_add_evidence() -> None:
    validator = DnsValidator(tuple(TerminalResolver(f'resolver-{index}') for index in range(3)))
    result = await execute_run('example.com', (TerminalRunSource(),), dns_validator=validator)

    legacy = legacy_json_result(
        result,
        {
            'cmd': 'theHarvester -d example.com',
            'emails': ['ops@example.com'],
            'hosts': ['legacy.example.com'],
        },
    )
    evidence_xml = ElementTree.fromstring(evidence_xml_fragment(result))

    assert legacy['cmd'] == 'theHarvester -d example.com'
    assert legacy['emails'] == ['ops@example.com']
    assert legacy['hosts'] == ['legacy.example.com', 'api.example.com']
    assert legacy['evidence_run']['status'] == 'complete'
    assert {item['value'] for item in legacy['evidence_run']['merged_results']} == {
        'api.example.com',
        'old.example.com',
        'related.example.net',
        'cdn.vendor.test',
    }
    assert evidence_xml.tag == 'evidence_run'
    assert evidence_xml.attrib['status'] == 'complete'
    assert evidence_xml.find("source[@name='fixture']").attrib['status'] == 'succeeded'
    assert {item.attrib['value'] for item in evidence_xml.findall('merged_result')} == {
        'api.example.com',
        'old.example.com',
        'related.example.net',
        'cdn.vendor.test',
    }


@pytest.mark.asyncio
async def test_structured_run_persistence_round_trips_in_its_own_table(tmp_path) -> None:
    result = await execute_run('example.com', (CompletedRunSource(),))
    store = SQLiteRunStore(tmp_path / 'stash.sqlite')

    await store.save(result)

    assert await store.load(result.run_id) == result.to_dict()


@pytest.mark.asyncio
async def test_cli_finishes_selected_stages_before_persisting_and_reporting(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import theHarvester.__main__ as main_module

    events: list[str] = []
    terminal_messages: list[str] = []
    wordlist = tmp_path / 'api-endpoints.txt'
    wordlist.write_text('/v1/status\n')
    report = tmp_path / 'completed-run'

    class FakeCrtshSearch:
        def __init__(self, _target: str) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            events.append('collect')

        async def get_hostnames(self) -> list[str]:
            return ['api.example.com']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

    class FakeDnsForce:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def run(self):
            events.append('dns-brute')
            return ['late.example.com:192.0.2.11'], ['late.example.com'], ['192.0.2.11']

    class FakeHostChecker:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def check(self):
            return (
                [
                    'api.example.com:192.0.2.10',
                    'api.example.com:198.51.100.10',
                ],
                ['api.example.com'],
                ['192.0.2.10', '198.51.100.10'],
            )

    async def fake_reverse_all_ips_in_range(*, iprange: str, **_kwargs) -> None:
        if iprange.startswith('192.0.2.10'):
            raise RuntimeError('one reverse range failed')
        await asyncio.sleep(0.05)
        events.append('dns-lookup')

    class FakeTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            return None

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, *, proxy: bool) -> None:
            assert proxy is False
            events.append('takeover')

        async def get_takeover_results(self) -> dict[str, str]:
            return {'api.example.com': 'not vulnerable'}

    class FakePool:
        def __init__(self, _workers: int) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, items):
            return [await function(item) for item in items]

    class FailedScreenShotter:
        output = 'screenshots'
        slash = '/'

        def __init__(self, _output: str) -> None:
            return None

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str):
            return host, ('https',)

        def chunk_list(self, hosts: list[str], _chunk_size: int):
            return (hosts,)

        async def take_screenshot(self, _host: str) -> None:
            raise RuntimeError('screenshot capture failed')

    class FakeApiScanner:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def do_search(self) -> None:
            events.append('api-scan')

        def get_found_endpoints(self):
            return {'https://example.com/v1/status': SimpleNamespace(status_code=200)}

        def get_interesting_endpoints(self):
            return {'https://example.com/v1/interesting': SimpleNamespace(status_code=200)}

        def get_auth_required(self):
            return {'https://example.com/v1/private': SimpleNamespace(status_code=401)}

        def get_api_versions(self):
            return {'v1'}

        def get_rate_limits(self):
            return {'https://example.com/v1/limited': SimpleNamespace(method='GET')}

        def get_methods(self):
            return {'GET'}

        def get_status_codes(self):
            return {200, 401, 429}

    class FakeShodanSearch:
        async def search_ip(self, ip: str):
            if ip == '198.51.100.10':
                return {ip: 'provider failed'}
            return {ip: {'product': 'raw-provider-secret'}}

    async def no_sleep(_seconds: float) -> None:
        return None

    class FakeRunStore:
        saved: ClassVar[list] = []

        async def save(self, result) -> None:
            events.append('persist')
            self.saved.append(result)

    def capture_terminal(result) -> str:
        events.append('terminal')
        return format_run_terminal(result)

    def capture_output(message: object, *_args, **_kwargs) -> None:
        terminal_messages.append(str(message))

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FakeHostChecker)
    monkeypatch.setattr(main_module.dnssearch, 'DnsForce', FakeDnsForce)
    monkeypatch.setattr(
        main_module.dnssearch,
        'serialize_ip_range',
        lambda *, ip, **_kwargs: f'{ip}/24',
    )
    monkeypatch.setattr(main_module.dnssearch, 'reverse_all_ips_in_range', fake_reverse_all_ips_in_range)
    monkeypatch.setattr(main_module.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(main_module, 'ScreenShotter', FailedScreenShotter)
    monkeypatch.setattr(main_module, 'Pool', FakePool)
    monkeypatch.setattr(main_module.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    monkeypatch.setattr(main_module.shodansearch, 'SearchShodan', FakeShodanSearch)
    monkeypatch.setattr(main_module.asyncio, 'sleep', no_sleep)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore, raising=False)
    monkeypatch.setattr(main_module, 'format_run_terminal', capture_terminal, raising=False)
    monkeypatch.setattr(main_module.output_logger, 'info', capture_output)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=True,
            dns_brute=True,
            dns_lookup=True,
            dns_resolve=None,
            dns_server=None,
            domain='example.com',
            filename=str(report),
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='screenshots',
            shodan=True,
            source='crtsh',
            start=0,
            take_over=True,
            wordlist=str(wordlist),
        ),
        return_evidence_run=True,
    )

    result = response[-1]
    terminal = '\n'.join(terminal_messages)
    assert events == ['collect', 'dns-brute', 'dns-lookup', 'takeover', 'api-scan', 'persist', 'terminal']
    assert result is FakeRunStore.saved[0]
    assert next(item for item in result.stage_executions if item.stage == 'action:screenshot').status is SourceStatus.FAILED
    assert {entity.value for entity in result.entities} == {'api.example.com', 'late.example.com'}
    assert {(item.kind, item.value) for item in result.selected_observations} == {
        (StageFindingKind.TAKEOVER, 'api.example.com'),
        (StageFindingKind.API_ENDPOINT, 'https://example.com/v1/status'),
        (StageFindingKind.INTERESTING_URL, 'https://example.com/v1/interesting'),
        (StageFindingKind.API_AUTH_REQUIRED, 'https://example.com/v1/private'),
        (StageFindingKind.API_VERSION, 'v1'),
        (StageFindingKind.API_RATE_LIMIT, 'https://example.com/v1/limited'),
        (StageFindingKind.HTTP_METHOD, 'GET'),
        (StageFindingKind.HTTP_STATUS_CODE, '200'),
        (StageFindingKind.HTTP_STATUS_CODE, '401'),
        (StageFindingKind.HTTP_STATUS_CODE, '429'),
        (StageFindingKind.SHODAN_RESULT, '192.0.2.10'),
    }
    assert next(item for item in result.stage_executions if item.stage == 'action:shodan').status is SourceStatus.FAILED
    legacy_json = json.loads(report.with_suffix('.json').read_text())
    evidence_xml = ElementTree.parse(report.with_suffix('.xml')).getroot().find('evidence_run')
    jsonl = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert legacy_json['evidence_run']['run_id'] == result.run_id
    assert evidence_xml.attrib['run_id'] == result.run_id
    assert {record['record_type'] for record in jsonl} >= {'run', 'stage_execution', 'selected_observation'}
    assert terminal.count('https://example.com/v1/status') == 1
    assert 'raw-provider-secret' not in terminal
    assert '[*] Interesting Urls found: 1' in terminal
    assert '[*] Endpoints requiring authentication: 1' in terminal
    assert '[*] Detected API versions: 1' in terminal
    assert '[*] Rate limited endpoints: 1' in terminal
    assert '[*] HTTP methods used: 1' in terminal
    assert '[*] HTTP status codes encountered: 3' in terminal

    from theHarvester.lib.api import api

    async def completed_start(_args, *, return_evidence_run: bool = False):
        assert return_evidence_run is True
        return (
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            ['api.example.com', 'late.example.com'],
            result,
        )

    monkeypatch.setattr(api.__main__, 'start', completed_start)
    monkeypatch.setattr(api.__main__.Core, 'get_supportedengines', lambda: ['fixture'])

    rest_response = TestClient(api.app).get('/query?domain=example.com&source=fixture')

    assert rest_response.status_code == 200
    assert rest_response.json()['evidence_run']['run_id'] == result.run_id
    assert {item['value'] for item in rest_response.json()['evidence_run']['merged_results']} == {
        'api.example.com',
        'late.example.com',
    }
    assert {(item['kind'], item['value']) for item in rest_response.json()['evidence_run']['selected_observations']} >= {
        ('takeover', 'api.example.com'),
        ('api-endpoint', 'https://example.com/v1/status'),
    }


@pytest.mark.asyncio
async def test_cli_dns_validates_legacy_source_before_reporting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    import theHarvester.__main__ as main_module

    candidate = 'www.example.com'
    report = tmp_path / 'legacy-source'

    class FakeCertSpotter:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return [candidate]

    class FakeVantage:
        def __init__(self, nameserver: str) -> None:
            self.name = nameserver

        async def query(self, hostname: str) -> DnsResponse:
            return DnsResponse(ipv4=('192.0.2.10',)) if hostname == candidate else DnsResponse(rcode='NXDOMAIN')

        async def close(self) -> None:
            return None

    class FakeHostChecker:
        def __init__(self, *_args: object) -> None:
            raise AssertionError('consensus validation must replace the legacy resolver path')

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args: object) -> None:
            return None

        async def store(self, *_args: object) -> None:
            return None

    class FakeRunStore:
        saved: ClassVar[list] = []

        async def save(self, result) -> None:
            self.saved.append(result)

    terminal_messages: list[str] = []
    monkeypatch.setattr(main_module.certspottersearch, 'SearchCertspoter', FakeCertSpotter)
    monkeypatch.setattr(main_module, 'AioDnsResolverVantage', FakeVantage, raising=False)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FakeHostChecker)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore, raising=False)
    monkeypatch.setattr(main_module.output_logger, 'info', lambda message, *_args: terminal_messages.append(str(message)))

    monkeypatch.setattr(
        main_module.sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'certspotter',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '-f',
            str(report),
            '-q',
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await main_module.start()

    assert exit_info.value.code == 0
    result = FakeRunStore.saved[0]
    legacy_json = json.loads(report.with_suffix('.json').read_text())
    evidence_xml = ElementTree.parse(report.with_suffix('.xml')).getroot().find('evidence_run')

    assert len(result.dns_validations) == 12
    assert result.entities[0].addressability == 'currently-addressable'
    assert legacy_json['hosts'] == [f'{candidate}:192.0.2.10']
    assert [item.attrib['value'] for item in evidence_xml.findall('merged_result')] == [candidate]
    assert '\n'.join(terminal_messages).count(f'{candidate} [status=currently-addressable') == 1
    assert FakeRunStore.saved == [result]


@pytest.mark.asyncio
async def test_cli_records_provider_people_in_the_completed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.__main__ as main_module

    class FakeVenacusSearch:
        def __init__(self, **_kwargs) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_emails(self) -> list[str]:
            return []

        async def get_ips(self) -> list[str]:
            return []

        async def get_people(self) -> list[dict[str, str]]:
            return [{'name': 'Alice'}]

        async def get_interestingurls(self) -> list[str]:
            return []

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

    class FakeRunStore:
        async def save(self, _result) -> None:
            return None

    monkeypatch.setattr(main_module.venacussearch, 'SearchVenacus', FakeVenacusSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=False,
            source='venacus',
            start=0,
            take_over=False,
            wordlist='',
        ),
        return_evidence_run=True,
    )

    result = response[-1]
    assert {(item.kind, item.value) for item in result.selected_observations} == {
        (StageFindingKind.PERSON, '{"name":"Alice"}')
    }
    assert all(item.collected_at >= result.started_at for item in result.selected_observations)


@pytest.mark.asyncio
async def test_cli_preserves_the_actual_provider_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.__main__ as main_module

    class FailedCrtshSearch:
        def __init__(self, _target: str) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            raise RuntimeError('provider failed')

        async def get_hostnames(self) -> list[str]:
            raise AssertionError('failed source must not expose results')

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

    class FakeRunStore:
        async def save(self, _result) -> None:
            return None

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FailedCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=False,
            source='crtsh',
            start=0,
            take_over=False,
            wordlist='',
        ),
        return_evidence_run=True,
    )

    execution = response[-1].source_executions[0]
    assert execution.status is SourceStatus.FAILED
    assert execution.error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_cli_preserves_shodan_provider_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    import theHarvester.__main__ as main_module

    class FailedShodanSearch:
        async def search_ip(self, _ip: str):
            raise RuntimeError('provider failed')

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

    class FakeRunStore:
        async def save(self, _result) -> None:
            return None

    monkeypatch.setattr(socket, 'gethostbyname', lambda _domain: '192.0.2.10')
    monkeypatch.setattr(main_module.shodansearch, 'SearchShodan', FailedShodanSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=False,
            source='shodan',
            start=0,
            take_over=False,
            wordlist='',
        ),
        return_evidence_run=True,
    )

    execution = response[-1].source_executions[0]
    assert execution.status is SourceStatus.FAILED
    assert execution.error_type == 'RuntimeError'


def test_rest_query_keeps_legacy_fields_and_adds_the_completed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from theHarvester.lib.api import api

    result = asyncio.run(execute_run('example.com', (TerminalRunSource(),)))

    async def fake_start(_args, *, return_evidence_run: bool = False):
        assert return_evidence_run is True
        return (
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            ['ops@example.com'],
            ['api.example.com'],
            result,
        )

    monkeypatch.setattr(api.__main__.Core, 'get_supportedengines', lambda: ['fixture'])
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.com&source=fixture')

    assert response.status_code == 200
    assert response.json()['emails'] == ['ops@example.com']
    assert response.json()['hosts'] == ['api.example.com', 'old.example.com']
    assert response.json()['evidence_run']['run_id'] == result.run_id
    assert {item['value'] for item in response.json()['evidence_run']['merged_results']} == {
        'api.example.com',
        'old.example.com',
        'related.example.net',
        'cdn.vendor.test',
    }


def test_rest_dnsbrute_keeps_legacy_results_and_failed_stage_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from theHarvester.lib.api import api

    result = asyncio.run(execute_run('example.com', ()))
    result = complete_run(
        result,
        (
            StageResult(
                'action:dns-brute',
                SourceStatus.FAILED,
                1,
                0,
                error_type='RuntimeError',
                is_action=True,
            ),
        ),
    )

    async def fake_start(_args, *, return_evidence_run: bool = False):
        assert return_evidence_run is True
        return [], result

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/dnsbrute?domain=example.com')

    assert response.status_code == 200
    assert response.json()['dns_bruteforce'] == []
    assert response.json()['evidence_run']['status'] == 'failed'
    assert response.json()['evidence_run']['stage_executions'][0]['status'] == 'failed'


@pytest.mark.parametrize(
    ('error', 'expected_run_status', 'expected_source_status'),
    [
        (RuntimeError('provider failed'), 'failed', 'failed'),
        (SourceRateLimitedError(), 'partial', 'rate-limited'),
    ],
)
@pytest.mark.asyncio
async def test_incomplete_source_states_remain_visible_on_every_output(
    error: Exception,
    expected_run_status: str,
    expected_source_status: str,
) -> None:
    result = await execute_run('example.com', (IncompleteRunSource(error),))

    terminal = format_run_terminal(result)
    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]
    legacy = legacy_json_result(result)
    evidence_xml = ElementTree.fromstring(evidence_xml_fragment(result))

    assert f'Run status: {expected_run_status}' in terminal
    assert f'fixture [status={expected_source_status}' in terminal
    assert records[0]['data']['status'] == expected_run_status
    assert legacy['evidence_run']['status'] == expected_run_status
    assert evidence_xml.attrib['status'] == expected_run_status


@pytest.mark.asyncio
async def test_late_source_failure_cannot_remain_a_complete_run() -> None:
    result = await execute_run('example.com', (CompletedRunSource(),))

    completed = complete_run(
        result,
        (
            StageResult(
                'fixture',
                SourceStatus.FAILED,
                1,
                0,
                error_type='RuntimeError',
            ),
        ),
    )

    assert completed.status is RunStatus.FAILED
    assert completed.source_executions[0].status is SourceStatus.FAILED
    assert completed.source_executions[0].error_type == 'RuntimeError'
