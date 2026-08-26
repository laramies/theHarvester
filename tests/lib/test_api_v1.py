from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient


def _jsonl_result(
    *,
    target: str = 'example.test',
    finding_type: str = 'email',
    value: str = 'a@example.test',
    finding_fields: dict[str, object] | None = None,
    summary_fields: dict[str, object] | None = None,
) -> str:
    summary = {
        'type': 'summary',
        'run_id': '9f9b4383-6cc4-4f3f-80a4-c8d21930dc2d',
        'target': target,
        'started_at': '2026-08-08T01:00:00Z',
        'completed_at': '2026-08-08T01:01:00Z',
        'evidence_status': 'complete',
        'result_count': 1,
        'counts': {finding_type: 1},
    }
    summary.update(summary_fields or {})
    return '\n'.join(
        (
            json.dumps(summary),
            json.dumps({'type': finding_type, 'value': value, 'sources': [], **(finding_fields or {})}),
            '',
        )
    )


def _vhost_observation(endpoint: str, hostname: str = 'admin.example.test') -> dict[str, object]:
    return {
        'endpoint': endpoint,
        'http_host': hostname,
        'tls_server_name': hostname,
        'classification': 'distinct',
        'phase': 'body',
        'status': 401,
        'location': None,
        'body_sha256': 'a' * 64,
        'body_size': 12,
        'body_truncated': False,
        'context_phase': 'body',
        'context_status': 200,
        'context_location': None,
        'context_body_sha256': 'a' * 64,
        'context_body_size': 12,
        'context_body_truncated': False,
        'control_phase': 'body',
        'control_status': 200,
        'control_location': None,
        'control_body_sha256': 'a' * 64,
        'control_body_size': 12,
        'control_body_truncated': False,
        'confirmation_body_sha256': None,
        'tls_verified': True,
        'distinct_signals': ['status'],
        'reflection_normalized': False,
    }


def _vhost_jsonl_result(*, target: str = 'example.test', value: str = 'admin.example.test') -> str:
    return _jsonl_result(
        target=target,
        finding_type='hostname',
        value=value,
        finding_fields={
            'actions': ['vhost'],
            'observations': [
                _vhost_observation('https://192.0.2.8:443/', value),
                _vhost_observation('https://192.0.2.9:443/', value),
            ],
        },
        summary_fields={
            'action_executions': [
                {
                    'action': 'vhost',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )


def _network_jsonl_result() -> str:
    summary = {
        'type': 'summary',
        'run_id': 'b4e1e2d3-cc10-42fa-b66e-ebacfe3acaa2',
        'target': 'example.test',
        'started_at': '2026-08-11T12:00:00Z',
        'completed_at': '2026-08-11T12:01:00Z',
        'evidence_status': 'complete',
        'result_count': 2,
        'counts': {'asn': 1, 'prefix': 1},
        'action_executions': [
            {
                'action': 'routeviews',
                'status': 'completed',
                'duration_ms': 1,
                'result_count': 1,
                'error_type': None,
                'stop_reason': None,
            }
        ],
    }
    prefix = {
        'type': 'prefix',
        'value': '203.0.113.0/24',
        'scope': 'external-relationship',
        'sources': [],
        'actions': ['routeviews'],
        'observations': [
            {
                'type': 'observed-origin',
                'action': 'routeviews',
                'origin_asn': 'AS64500',
                'collected_at': '2026-08-11T12:01:00Z',
            },
            {
                'type': 'bgp-route',
                'action': 'routeviews',
                'origin_asn': 'AS64500',
                'collector': 'route-views.test',
                'peer_asn': 'AS64496',
                'peer_address': '192.0.2.7',
                'as_path': '64496 64500',
                'communities': '',
                'observed_at': '2026-08-11T12:00:00Z',
                'collected_at': '2026-08-11T12:01:00Z',
            },
            {
                'type': 'rpki-validation',
                'action': 'routeviews',
                'origin_asn': 'AS64500',
                'state': 'valid',
                'observed_at': '2026-08-11T12:00:00Z',
                'collected_at': '2026-08-11T12:01:00Z',
            },
        ],
    }
    return '\n'.join(
        (json.dumps(summary), json.dumps({'type': 'asn', 'value': 'AS64500', 'sources': []}), json.dumps(prefix), '')
    )


def _asn_attribution_jsonl_result() -> str:
    summary = {
        'type': 'summary',
        'run_id': 'e149aef3-f4c5-4145-82f3-71d11d51d9cd',
        'target': 'example.test',
        'started_at': '2026-08-12T12:00:00Z',
        'completed_at': '2026-08-12T12:01:00Z',
        'evidence_status': 'complete',
        'result_count': 3,
        'counts': {'asn': 1, 'hostname': 1, 'ip': 1},
        'source_executions': [
            {
                'source': 'urlscan',
                'status': 'completed',
                'duration_ms': 1,
                'result_count': 3,
                'error_type': None,
                'stop_reason': None,
            }
        ],
    }
    findings = [
        {
            'type': 'asn',
            'value': 'AS64500',
            'sources': ['urlscan'],
            'observations': [
                {
                    'type': 'organization-attribution',
                    'producer_kind': 'source',
                    'producer': 'urlscan',
                    'organization_label': 'Example Network',
                    'subject': {'type': 'hostname', 'value': 'api.example.test'},
                    'collected_at': '2026-08-12T12:01:00Z',
                },
                {
                    'type': 'organization-attribution',
                    'producer_kind': 'source',
                    'producer': 'urlscan',
                    'organization_label': 'Example Network',
                    'subject': {'type': 'ip', 'value': '192.0.2.10'},
                    'collected_at': '2026-08-12T12:01:00Z',
                },
            ],
        },
        {'type': 'hostname', 'value': 'api.example.test', 'sources': ['urlscan']},
        {'type': 'ip', 'value': '192.0.2.10', 'sources': ['urlscan']},
    ]
    return '\n'.join((json.dumps(summary), *(json.dumps(finding) for finding in findings), ''))


@pytest.mark.parametrize(
    ('finding_type', 'finding_fields'),
    [
        ('made-up-kind', {}),
        ('api-endpoint', {}),
        ('interesting-url', {}),
        ('ip-address', {}),
        ('linkedin-link', {}),
        ('subdomain', {}),
        ('vhost', {}),
        ('hostname', {'dns_status': 'made-up-status'}),
    ],
)
def test_api_rejects_jsonl_findings_outside_the_contract(
    tmp_path,
    monkeypatch,
    finding_type: str,
    finding_fields: dict[str, object],
) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'invalid.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=_jsonl_result(finding_type=finding_type, finding_fields=finding_fields),
        )

    assert response.status_code == 400


def test_api_exposes_one_fresh_run_contract(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        schema = client.get('/openapi.json').json()
        paths = set(schema['paths'])
        old_responses = [
            client.get('/query?domain=example.test&source=crtsh'),
            client.get('/sources'),
            client.get('/dnsbrute?domain=example.test'),
            client.get('/runs'),
            client.post('/additional/all', json={'domain': 'example.test'}),
        ]

    assert paths == {
        '/api/v1/sources',
        '/api/v1/runs',
        '/api/v1/runs/import',
        '/api/v1/runs/import-database',
        '/api/v1/runs/export-database',
        '/api/v1/runs/{run_id}',
        '/api/v1/runs/{run_id}/cancel',
        '/api/v1/runs/{run_id}/export',
        '/api/v1/runs/{run_id}/screenshots/{name}',
        '/api/v1/schedules',
        '/api/v1/schedules/health',
        '/api/v1/schedules/{schedule_id}',
        '/api/v1/schedules/{schedule_id}/dispatches',
        '/api/v1/schedules/{schedule_id}/pause',
        '/api/v1/schedules/{schedule_id}/resume',
        '/api/v1/schedules/{schedule_id}/run-now',
    }
    assert all(response.status_code == 404 for response in old_responses)


def test_screenshot_route_serves_only_a_run_owned_png(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app, client=('127.0.0.2', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'smoke.jsonl'},
            headers=headers,
            content=_jsonl_result(
                finding_type='hostname',
                value='owned.example.test',
                summary_fields={
                    'action_executions': [
                        {
                            'action': 'screenshot',
                            'status': 'completed',
                            'duration_ms': 1,
                            'result_count': 0,
                            'error_type': None,
                            'stop_reason': None,
                        }
                    ],
                    'artifacts': [
                        {
                            'action': 'screenshot',
                            'kind': 'screenshot',
                            'subject': {'kind': 'hostname', 'value': 'owned.example.test'},
                            'file': {
                                'path': 'screenshots/owned.example.test.png',
                                'media_type': 'image/png',
                                'size_bytes': 16,
                                'sha256': '0' * 64,
                            },
                            'created_at': '2026-08-08T01:01:00Z',
                        }
                    ],
                },
            ),
        )
        assert imported.status_code == 201
        run_id = imported.json()['run_id']
        screenshot_dir = tmp_path / 'artifacts' / run_id / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        (screenshot_dir / 'owned.example.test.png').write_bytes(b'owned screenshot')
        (screenshot_dir / 'unrecorded.png').write_bytes(b'unrecorded screenshot')
        outside = tmp_path / 'outside.png'
        outside.write_bytes(b'outside screenshot')
        (screenshot_dir / 'linked.png').symlink_to(outside)

        owned = client.get(f'/api/v1/runs/{run_id}/screenshots/owned.example.test.png', headers=headers)
        unrecorded = client.get(f'/api/v1/runs/{run_id}/screenshots/unrecorded.png', headers=headers)
        linked = client.get(f'/api/v1/runs/{run_id}/screenshots/linked.png', headers=headers)
        traversal = client.get(f'/api/v1/runs/{run_id}/screenshots/%2E%2E%2Foutside.png', headers=headers)

    assert owned.status_code == 200
    assert owned.content == b'owned screenshot'
    assert unrecorded.status_code == 404
    assert linked.status_code == 404
    assert traversal.status_code == 404


def test_openapi_names_the_public_response_shapes(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        schema = client.get('/openapi.json').json()

    paths = schema['paths']
    assert paths['/api/v1/sources']['get']['responses']['200']['content']['application/json']['schema'] == {
        '$ref': '#/components/schemas/SourceCatalogResponse'
    }
    assert paths['/api/v1/runs']['get']['responses']['200']['content']['application/json']['schema']['items'] == {
        '$ref': '#/components/schemas/RunSummary'
    }
    for path, method in (
        ('/api/v1/runs', 'post'),
        ('/api/v1/runs/import', 'post'),
        ('/api/v1/runs/{run_id}', 'get'),
        ('/api/v1/runs/{run_id}/cancel', 'post'),
    ):
        assert paths[path][method]['responses']['201' if path in {'/api/v1/runs', '/api/v1/runs/import'} else '200']['content'][
            'application/json'
        ]['schema'] == {'$ref': '#/components/schemas/RunDetail'}


def test_source_catalog_exposes_shared_action_activities(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.core import Core

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(
        Core,
        'api_keys',
        staticmethod(lambda: {'censys': {'token': 'configured-token'}, 'fofa': {'key': '', 'email': ''}}),
    )

    with TestClient(api.app) as client:
        response = client.get('/api/v1/sources', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 200
    catalog = response.json()
    assert catalog['sources']
    censys = next(source for source in catalog['sources'] if source['name'] == 'censys')
    assert censys['credentials'] == ['api-token']
    assert censys['ready'] is True
    fofa = next(source for source in catalog['sources'] if source['name'] == 'fofa')
    assert fofa['ready'] is False
    crtsh = next(source for source in catalog['sources'] if source['name'] == 'crtsh')
    assert crtsh['ready'] is True
    assert catalog['actions'] == [
        {'name': 'api-scan', 'activity': 'P2'},
        {'name': 'dns-brute', 'activity': 'P1'},
        {'name': 'dns-lookup', 'activity': 'P1'},
        {'name': 'dns-recursive', 'activity': 'P1'},
        {'name': 'dns-resolve', 'activity': 'P1'},
        {'name': 'routeviews', 'activity': 'P0'},
        {'name': 'screenshot', 'activity': 'P2'},
        {'name': 'shodan', 'activity': 'P0'},
        {'name': 'takeover', 'activity': 'P2'},
        {'name': 'vhost', 'activity': 'P2'},
    ]


def test_openapi_explains_scope_and_execution_controls(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        schema = client.get('/openapi.json').json()

    request_body = schema['paths']['/api/v1/runs']['post']['requestBody']
    properties = request_body['content']['application/json']['schema']['properties']

    assert request_body['required'] is True
    assert 'union' in properties['sources']['description']
    assert 'do not filter' in properties['sources']['description']
    assert '/24' in properties['dns_lookup']['description']
    assert 'whole run' in properties['deadline_seconds']['description']
    assert 'recursive DNS runs default to unlimited' in properties['deadline_seconds']['description']
    assert 'not establish ownership' in properties['routeviews']['description']
    assert (
        'discovered IPs with sourced ASN attribution, or an explicitly targeted ASN or IP address'
        in properties['routeviews']['description']
    )
    assert 'prefix' not in properties['routeviews']['description']
    assert 'three resolver' in properties['dns_recursive_query_limit']['description']
    assert 'discovery sources' in properties['proxies']['description']
    assert 'Direct DNS' in properties['proxies']['description']
    assert 'Exclude hostname results' in properties['no_hosts']['description']
    assert 'direct transport' in properties['takeover']['description']
    assert 'take_over' not in properties
    assert 'endpoint paths' in properties['api_scan_paths']['description']
    import_content = schema['paths']['/api/v1/runs/import']['post']['requestBody']['content']
    assert set(import_content) == {'application/x-ndjson'}
    database_export_content = schema['paths']['/api/v1/runs/export-database']['get']['responses']['200']['content']
    assert set(database_export_content) == {'application/vnd.sqlite3'}
    assert database_export_content['application/vnd.sqlite3']['schema']['description'] == (
        'Portable SQLite database containing every completed run and no API lifecycle state.'
    )
    export_content = schema['paths']['/api/v1/runs/{run_id}/export']['get']['responses']['200']['content']
    assert set(export_content) == {'application/x-ndjson'}
    assert set(schema['components']['schemas']['NormalizedResult']['properties']) == {
        'type',
        'value',
        'sources',
        'actions',
        'scope',
        'observations',
        'details',
    }
    assert 'VirtualHostResult' not in schema['components']['schemas']
    assert export_content['application/x-ndjson']['schema']['description'] == (
        'UTF-8 JSONL with one summary followed by normalized findings.'
    )

    def references(value):
        if isinstance(value, dict):
            if '$ref' in value:
                yield value['$ref']
            for child in value.values():
                yield from references(child)
        elif isinstance(value, list):
            for child in value:
                yield from references(child)

    components = schema['components']['schemas']
    for reference in references(schema):
        assert reference.startswith('#/components/schemas/')
        assert reference.removeprefix('#/components/schemas/') in components


def test_dns_limits_default_to_unlimited_and_keep_explicit_values() -> None:
    from theHarvester.lib.api.run_models import RunRequest

    default = RunRequest(target='example.test', sources=['crtsh'])
    dns_default = RunRequest(target='example.test', sources=['crtsh'], dns_resolve=True)
    dns_brute_default = RunRequest(target='example.test', sources=[], dns_brute=True)
    explicit = RunRequest(
        target='example.test',
        sources=['crtsh'],
        deadline_seconds=60,
        dns_recursive_query_limit=12,
        dns_recursive_runtime_seconds=1.5,
    )

    assert default.deadline_seconds == 1800
    assert dns_default.deadline_seconds is None
    assert dns_brute_default.deadline_seconds == 1800
    assert default.dns_recursive_query_limit is None
    assert default.dns_recursive_runtime_seconds is None
    assert explicit.deadline_seconds == 60
    assert (explicit.dns_recursive_query_limit, explicit.dns_recursive_runtime_seconds) == (12, 1.5)


def test_result_limit_accepts_unlimited_and_has_no_numeric_ceiling() -> None:
    from theHarvester.lib.api.run_models import RunRequest

    unlimited = RunRequest(target='example.test', sources=['crtsh'], limit=0)
    large = RunRequest(target='example.test', sources=['crtsh'], limit=1_000_000)

    assert unlimited.limit == 0
    assert large.limit == 1_000_000


def test_run_detail_exposes_one_normalized_evidence_surface(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'result.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=_jsonl_result(),
        )

    assert imported.status_code == 201
    assert 'evidence' not in imported.json()


def test_api_scan_can_run_without_discovery_sources(tmp_path, monkeypatch) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(target='example.test', sources=[], api_scan=True, api_scan_paths=['/api/v2', '/health'])

    assert request.api_scan is True
    assert request.api_scan_paths == ['/api/v2', '/health']
    with pytest.raises(ValidationError):
        RunRequest(target='example.test', sources=[], api_scan=True, api_scan_paths=['https://other.example/api'])


def test_routeviews_accepts_only_an_action_only_asn_target() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(target='as64500', sources=[], routeviews=True)

    assert request.target == 'AS64500'
    with pytest.raises(ValidationError, match='ASN target requires RouteViews as the only selected work'):
        RunRequest(target='AS64500', sources=['crtsh'], routeviews=True)
    with pytest.raises(ValidationError, match='ASN target requires RouteViews as the only selected work'):
        RunRequest(target='AS64500', sources=[], routeviews=True, shodan=True)


def test_routeviews_hostname_target_requires_a_discovery_source() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match='RouteViews hostname target requires a discovery source'):
        RunRequest(target='api.example.com', sources=[], routeviews=True)
    assert RunRequest(target='192.0.2.7', sources=[], routeviews=True).routeviews is True


def test_fresh_api_uses_catalog_takeover_name_and_rejects_unknown_fields() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(target='example.test', sources=[], takeover=True)

    assert request.takeover is True
    with pytest.raises(ValidationError):
        RunRequest(target='example.test', sources=[], take_over=True)


@pytest.mark.parametrize(
    'request_fields',
    [
        {'sources': ['shodan']},
        {'sources': ['shodanInternetDB']},
        {'sources': [], 'takeover': True},
        {'sources': [], 'dns_lookup': True},
    ],
)
def test_api_rejects_direct_dns_work_in_proxy_mode(request_fields: dict[str, object]) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match='Direct DNS'):
        RunRequest(target='example.test', proxies=True, **request_fields)


def test_api_rejects_screenshot_capture_in_proxy_mode() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match='Screenshot capture supports direct transport only'):
        RunRequest(target='example.test', sources=[], screenshot=True, proxies=True)


@pytest.mark.parametrize(
    ('evidence_status', 'execution_status'),
    [('complete', 'failed'), ('partial', 'completed')],
)
def test_api_rejects_evidence_status_that_disagrees_with_executions(
    tmp_path,
    monkeypatch,
    evidence_status,
    execution_status,
) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    payload = _jsonl_result(
        summary_fields={
            'evidence_status': evidence_status,
            'source_executions': [
                {
                    'source': 'crtsh',
                    'status': execution_status,
                    'duration_ms': 1,
                    'result_count': 0,
                    'error_type': 'RuntimeError',
                    'stop_reason': 'provider-error',
                }
            ],
        },
        finding_fields={'sources': []},
    )

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'inconsistent.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 400
    assert response.json()['detail'] == 'Evidence status does not match its execution outcomes'


def test_api_preserves_sparse_failed_status_without_executions(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    database = tmp_path / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(database))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    payload = _jsonl_result(summary_fields={'evidence_status': 'failed'})

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'failed.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers={'X-API-Key': 'test-key'})

    assert imported.status_code == 201
    assert imported.json()['evidence_status'] == 'failed'
    assert json.loads(exported.text.splitlines()[0])['evidence_status'] == 'failed'


def test_api_import_and_export_accept_only_jsonl(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app, client=('127.0.0.3', 50000)) as client:
        rejected = client.post(
            '/api/v1/runs/import',
            params={'filename': 'legacy.json'},
            headers=headers,
            content='{"target":"example.test"}',
        )
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'result.jsonl'},
            headers={**headers, 'Content-Type': 'application/x-ndjson'},
            content=_jsonl_result(),
        )
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'round-trip.jsonl'},
            headers={**headers, 'Content-Type': 'application/x-ndjson'},
            content=exported.content,
        )
        old_json = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/exports/json', headers=headers)
        old_csv = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/exports/csv', headers=headers)

    assert rejected.status_code == 400
    assert rejected.json()['detail'] == 'Choose a .jsonl result file'
    assert imported.status_code == 201
    assert exported.status_code == 200
    assert exported.headers['content-type'] == 'application/x-ndjson'
    assert exported.headers['content-disposition'].endswith('.jsonl"')
    records = [json.loads(line) for line in exported.text.splitlines()]
    assert 'schema' not in records[0]
    assert 'schema_version' not in records[0]
    assert records[0]['type'] == 'summary'
    assert records[0]['target'] == 'example.test'
    assert records[1] == {'sources': [], 'type': 'email', 'value': 'a@example.test'}
    assert reimported.status_code == 201
    assert reimported.json()['results'] == [{'type': 'email', 'value': 'a@example.test', 'sources': [], 'actions': []}]
    assert old_json.status_code == 404
    assert old_csv.status_code == 404


def test_api_jsonl_round_trip_preserves_canonical_url_sources(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key', 'Content-Type': 'application/x-ndjson'}
    sources = ['builtwith', 'gitlab', 'rocketreach']
    executions = [
        {
            'source': source,
            'status': 'completed',
            'duration_ms': 1,
            'result_count': 1,
            'error_type': None,
            'stop_reason': None,
        }
        for source in sources
    ]
    payload = _jsonl_result(
        finding_type='url',
        value='https://example.test/profile',
        finding_fields={'sources': sources},
        summary_fields={'source_executions': executions},
    )

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'urls.jsonl'},
            headers=headers,
            content=payload,
        )
        run_id = imported.json()['run_id']
        detail = client.get(f'/api/v1/runs/{run_id}', headers={'X-API-Key': 'test-key'})
        exported = client.get(f'/api/v1/runs/{run_id}/export', headers={'X-API-Key': 'test-key'})

    assert imported.status_code == 201
    assert detail.json()['results'] == [
        {
            'type': 'url',
            'value': 'https://example.test/profile',
            'sources': sources,
            'actions': [],
        }
    ]
    records = [json.loads(line) for line in exported.text.splitlines()]
    assert records[1] == {'sources': sources, 'type': 'url', 'value': 'https://example.test/profile'}


def test_api_database_import_rejects_non_sqlite_content(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import-database',
            params={'filename': 'results.sqlite'},
            headers={'X-API-Key': 'test-key', 'Content-Type': 'application/vnd.sqlite3'},
            content=b'not a sqlite database',
        )

    assert response.status_code == 400
    assert response.json()['detail'] == 'Uploaded file is not a SQLite database'


def test_api_database_import_exposes_completed_cli_runs(tmp_path, monkeypatch) -> None:
    from datetime import UTC, datetime

    from theHarvester.lib.api import api
    from theHarvester.lib.completed_result import CompletedResult
    from theHarvester.lib.database import ResultStore, dispose_sqlite_databases

    source_database = tmp_path / 'source.sqlite'
    destination_database = tmp_path / 'destination.sqlite'
    now = datetime.now(UTC)
    completed = CompletedResult.finish(
        target='imported.example.test',
        started_at=now,
        completed_at=now,
        groups={'hostname': ['api.imported.example.test']},
    )

    async def seed() -> None:
        store = ResultStore(source_database)
        await store.initialize()
        await store.save_run(completed)
        await dispose_sqlite_databases()

    asyncio.run(seed())
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(destination_database))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import-database',
            params={'filename': 'source.sqlite'},
            headers={'X-API-Key': 'test-key', 'Content-Type': 'application/vnd.sqlite3'},
            content=source_database.read_bytes(),
        )
        detail = client.get(
            f'/api/v1/runs/{completed.run_id}',
            headers={'X-API-Key': 'test-key'},
        )

    assert imported.status_code == 201
    assert imported.json()['imported_run_ids'] == [str(completed.run_id)]
    assert detail.status_code == 200
    assert detail.json()['results'] == [{'type': 'hostname', 'value': 'api.imported.example.test', 'sources': [], 'actions': []}]


def test_api_database_export_round_trip_contains_only_completed_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    source_database = tmp_path / 'source.sqlite'
    destination_database = tmp_path / 'destination.sqlite'
    exported_database = tmp_path / 'exported.sqlite'
    headers = {'X-API-Key': 'test-key'}
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(source_database))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    vhost_records = [json.loads(line) for line in _vhost_jsonl_result().splitlines()]
    vhost_records[0]['source_executions'] = [
        {
            'source': 'crtsh',
            'status': 'completed',
            'duration_ms': 2,
            'result_count': 1,
            'error_type': None,
            'stop_reason': None,
        }
    ]
    vhost_records[0]['action_executions'].append(
        {
            'action': 'screenshot',
            'status': 'completed',
            'duration_ms': 1,
            'result_count': 0,
            'error_type': None,
            'stop_reason': None,
        }
    )
    vhost_records[0]['artifacts'] = [
        {
            'action': 'screenshot',
            'kind': 'screenshot',
            'subject': {'kind': 'hostname', 'value': 'admin.example.test'},
            'file': {
                'path': 'screenshots/admin.example.test.png',
                'media_type': 'image/png',
                'size_bytes': 16,
                'sha256': '0' * 64,
            },
            'created_at': '2026-08-08T01:01:00Z',
        }
    ]
    vhost_records[1]['sources'] = ['crtsh']
    vhost_jsonl = ''.join(json.dumps(record) + '\n' for record in vhost_records)

    with TestClient(api.app) as client:
        first = client.post(
            '/api/v1/runs/import',
            params={'filename': 'vhost.jsonl'},
            headers=headers,
            content=vhost_jsonl,
        )
        second = client.post(
            '/api/v1/runs/import',
            params={'filename': 'network.jsonl'},
            headers=headers,
            content=_network_jsonl_result(),
        )
        source_details = {
            run_id: client.get(f'/api/v1/runs/{run_id}', headers=headers).json()
            for run_id in (first.json()['run_id'], second.json()['run_id'])
        }
        exported = client.get('/api/v1/runs/export-database', headers=headers)

    assert first.status_code == 201
    assert second.status_code == 201
    assert exported.status_code == 200
    assert exported.headers['content-type'] == 'application/vnd.sqlite3'
    assert exported.headers['content-disposition'] == 'attachment; filename="theharvester-completed-runs.sqlite"'
    assert exported.content.startswith(b'SQLite format 3\x00')
    exported_database.write_bytes(exported.content)
    with sqlite3.connect(exported_database) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {'runs', 'results'} <= tables
    assert {'run_records', 'run_worker_leases'}.isdisjoint(tables)

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(destination_database))
    with TestClient(api.app) as client:
        reimported = client.post(
            '/api/v1/runs/import-database',
            params={'filename': 'theharvester-completed-runs.sqlite'},
            headers={**headers, 'Content-Type': 'application/vnd.sqlite3'},
            content=exported.content,
        )
        imported_details = {
            run_id: client.get(f'/api/v1/runs/{run_id}', headers=headers).json()
            for run_id in reimported.json()['imported_run_ids']
        }

    assert reimported.status_code == 201
    assert reimported.json()['imported_run_ids'] == sorted((first.json()['run_id'], second.json()['run_id']))
    canonical_evidence_fields = (
        'run_id',
        'target',
        'started_at',
        'completed_at',
        'evidence_status',
        'result_count',
        'source_executions',
        'action_executions',
        'artifacts',
        'results',
    )
    assert {
        run_id: {field: detail[field] for field in canonical_evidence_fields} for run_id, detail in imported_details.items()
    } == {run_id: {field: detail[field] for field in canonical_evidence_fields} for run_id, detail in source_details.items()}


def test_api_jsonl_round_trip_preserves_source_attribution(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    source_execution = {
        'source': 'crtsh',
        'status': 'completed',
        'duration_ms': 0,
        'result_count': 1,
        'error_type': None,
        'stop_reason': None,
    }
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app, client=('127.0.0.4', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'complete.jsonl'},
            headers=headers,
            content=_jsonl_result(
                finding_fields={'sources': ['crtsh']},
                summary_fields={'source_executions': [source_execution]},
            ),
        )
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'complete-round-trip.jsonl'},
            headers=headers,
            content=exported.content,
        )

    summary = json.loads(exported.text.splitlines()[0])
    assert imported.json()['evidence_status'] == 'complete'
    assert imported.json()['source_executions'] == [source_execution]
    assert imported.json()['results'] == [{'type': 'email', 'value': 'a@example.test', 'sources': ['crtsh'], 'actions': []}]
    assert summary['run_id'] == imported.json()['run_id']
    assert summary['evidence_status'] == 'complete'
    assert summary['source_executions'] == [source_execution]
    assert json.loads(exported.text.splitlines()[1])['sources'] == ['crtsh']
    assert reimported.json()['evidence_status'] == 'complete'
    assert reimported.json()['request']['source_run_id'] == imported.json()['run_id']
    assert reimported.json()['source_executions'] == [source_execution]


def test_run_detail_reports_unique_hostname_contribution_per_source(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    summary = {
        'type': 'summary',
        'run_id': '31ced47a-6354-4f18-b633-2583400c4aad',
        'target': 'example.test',
        'started_at': '2026-08-23T12:00:00Z',
        'completed_at': '2026-08-23T12:01:00Z',
        'evidence_status': 'partial',
        'result_count': 2,
        'counts': {'hostname': 2},
        'source_executions': [
            {
                'source': 'crtsh',
                'status': 'completed',
                'duration_ms': 1,
                'result_count': 1,
                'error_type': None,
                'stop_reason': None,
            },
            {
                'source': 'subdomainapi',
                'status': 'partial',
                'duration_ms': 2,
                'result_count': 2,
                'error_type': None,
                'stop_reason': 'provider-limit',
            },
        ],
        'action_executions': [
            {
                'action': 'dns-resolve',
                'status': 'completed',
                'duration_ms': 3,
                'result_count': 1,
                'error_type': None,
                'stop_reason': None,
            }
        ],
    }
    payload = '\n'.join(
        (
            json.dumps(summary),
            json.dumps(
                {
                    'type': 'hostname',
                    'value': 'shared.example.test',
                    'sources': ['crtsh', 'subdomainapi'],
                }
            ),
            json.dumps(
                {
                    'type': 'hostname',
                    'value': 'unique.example.test',
                    'sources': ['subdomainapi'],
                    'actions': ['dns-resolve'],
                }
            ),
            '',
        )
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'source-yields.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 201
    assert response.json()['source_yields'] == [
        {
            'source': 'crtsh',
            'observed_result_count': 1,
            'unique_result_count': 0,
            'shared_result_count': 1,
            'resolved_hostname_count': 0,
            'unique_resolved_hostname_count': 0,
        },
        {
            'source': 'subdomainapi',
            'observed_result_count': 2,
            'unique_result_count': 1,
            'shared_result_count': 1,
            'resolved_hostname_count': 1,
            'unique_resolved_hostname_count': 1,
        },
    ]


def test_api_jsonl_export_uses_evidence_timestamps_not_lifecycle_timestamps(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    store = RunStore()
    queued = asyncio.run(store.create(RunRequest(target='example.test', sources=['crtsh'])))
    asyncio.run(store.claim_next())
    asyncio.run(
        store.finish(
            queued['run_id'],
            {
                'run_id': '3e7cf0c1-214b-4429-80ba-058b2cb68b06',
                'target': 'example.test',
                'status': 'complete',
                'started_at': '2026-08-07T01:00:00Z',
                'completed_at': '2026-08-07T01:01:00Z',
                'results': [],
                'source_executions': [],
            },
            '',
        )
    )

    with TestClient(api.app, client=('127.0.0.16', 50000)) as client:
        response = client.get(
            f'/api/v1/runs/{queued["run_id"]}/export',
            headers={'X-API-Key': 'test-key'},
        )

    summary = json.loads(response.text.splitlines()[0])
    completed = asyncio.run(store.load_completed_result(queued['run_id']))
    assert completed is not None
    assert response.text == completed.jsonl()
    assert summary['started_at'] == '2026-08-07T01:00:00Z'
    assert summary['completed_at'] == '2026-08-07T01:01:00Z'


def test_api_jsonl_export_uses_lifecycle_timestamps_for_sparse_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    store = RunStore()
    queued = asyncio.run(store.create(RunRequest(target='example.test', sources=['crtsh'])))
    asyncio.run(store.claim_next())
    asyncio.run(
        store.fail(
            queued['run_id'],
            'Provider process exited.',
            '',
            evidence={
                'run_id': 'eb470313-d813-4d81-bd75-c1221a8bc00e',
                'target': 'example.test',
                'status': 'partial',
                'results': [],
                'source_executions': [],
            },
        )
    )

    with TestClient(api.app, client=('127.0.0.17', 50000)) as client:
        exported = client.get(
            f'/api/v1/runs/{queued["run_id"]}/export',
            headers={'X-API-Key': 'test-key'},
        )
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'partial.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=exported.content,
        )

    summary = json.loads(exported.text.splitlines()[0])
    assert exported.status_code == 200
    assert isinstance(summary['started_at'], str)
    assert isinstance(summary['completed_at'], str)
    assert reimported.status_code == 201
    assert summary['evidence_status'] == 'partial'
    assert reimported.json()['evidence_status'] == 'partial'


def test_api_jsonl_round_trip_uses_canonical_hostname_and_ip_kinds(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    for client_ip, finding_type, value, run_id in (
        ('127.0.0.5', 'hostname', 'www.example.test', '0f17b751-dd31-46da-968f-31580e233b72'),
        ('127.0.0.6', 'ip', '192.0.2.1', 'f7419165-d78c-4aef-9023-e9686f864ff0'),
    ):
        with TestClient(api.app, client=(client_ip, 50000)) as client:
            imported = client.post(
                '/api/v1/runs/import',
                params={'filename': f'{finding_type}.jsonl'},
                headers=headers,
                content=_jsonl_result(finding_type=finding_type, value=value, summary_fields={'run_id': run_id}),
            )
            exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
            reimported = client.post(
                '/api/v1/runs/import',
                params={'filename': f'{finding_type}-round-trip.jsonl'},
                headers=headers,
                content=exported.content,
            )

        assert imported.json()['results'] == [{'type': finding_type, 'value': value, 'sources': [], 'actions': []}]
        assert json.loads(exported.text.splitlines()[1]) == {'sources': [], 'type': finding_type, 'value': value}
        assert reimported.json()['results'] == [{'type': finding_type, 'value': value, 'sources': [], 'actions': []}]


def test_api_jsonl_round_trip_preserves_grouped_virtual_host_observations(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app, client=('127.0.0.18', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'vhost.jsonl'},
            headers=headers,
            content=_vhost_jsonl_result(),
        )
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'vhost-round-trip.jsonl'},
            headers=headers,
            content=exported.content,
        )

    expected = {
        'type': 'hostname',
        'value': 'admin.example.test',
        'sources': [],
        'actions': ['vhost'],
        'observations': [
            _vhost_observation('https://192.0.2.8:443/'),
            _vhost_observation('https://192.0.2.9:443/'),
        ],
    }
    assert imported.status_code == 201
    assert imported.json()['results'] == [expected]
    assert imported.json()['result_count'] == 1
    assert json.loads(exported.text.splitlines()[1]) == expected
    assert reimported.status_code == 201
    assert reimported.json()['results'] == [expected]


def test_api_jsonl_round_trip_preserves_structured_network_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    expected = [json.loads(line) for line in _network_jsonl_result().splitlines()[1:]]
    expected[0]['actions'] = []

    with TestClient(api.app, client=('127.0.0.20', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'network.jsonl'},
            headers=headers,
            content=_network_jsonl_result(),
        )
        assert imported.status_code == 201, imported.text
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'network-round-trip.jsonl'},
            headers=headers,
            content=exported.content,
        )

    assert imported.json()['results'] == expected
    assert imported.json()['result_count'] == 2
    assert [json.loads(line) for line in exported.text.splitlines()[1:]] == [
        {key: value for key, value in expected[0].items() if key != 'actions'},
        expected[1],
    ]
    assert reimported.status_code == 201
    assert reimported.json()['results'] == expected


def test_api_jsonl_round_trip_preserves_asn_organization_attribution(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    expected = [json.loads(line) for line in _asn_attribution_jsonl_result().splitlines()[1:]]
    for finding in expected:
        finding['actions'] = []

    with TestClient(api.app, client=('127.0.0.21', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'asn-attribution.jsonl'},
            headers=headers,
            content=_asn_attribution_jsonl_result(),
        )
        assert imported.status_code == 201, imported.text
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'asn-attribution-round-trip.jsonl'},
            headers=headers,
            content=exported.content,
        )

    assert imported.json()['results'] == expected
    assert [json.loads(line) for line in exported.text.splitlines()[1:]] == [
        {key: value for key, value in finding.items() if key != 'actions'} for finding in expected
    ]
    assert reimported.status_code == 201
    assert reimported.json()['results'] == expected


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('sources', 'sourcegraph'),
        ('sources', ['']),
        ('actions', 'routeviews'),
        ('actions', ['']),
    ],
)
def test_api_evidence_rejects_invalid_network_producers(field: str, value: object) -> None:
    from fastapi import HTTPException

    from theHarvester.lib.api.run_evidence import validate_evidence

    records = [json.loads(line) for line in _network_jsonl_result().splitlines()]
    evidence = {
        'target': records[0]['target'],
        'status': records[0]['evidence_status'],
        'started_at': records[0]['started_at'],
        'completed_at': records[0]['completed_at'],
        'results': records[1:],
        'source_executions': [],
        'action_executions': records[0]['action_executions'],
        'artifacts': [],
    }
    evidence['results'][1][field] = value

    with pytest.raises(HTTPException, match='Network evidence producers must be arrays of non-empty strings'):
        validate_evidence(evidence)


@pytest.mark.parametrize(
    ('target', 'hostname'),
    [
        ('example.test', 'example.test'),
        ('example.test', 'admin.other.test'),
        ('192.0.2.8', 'admin.192.0.2.8'),
    ],
)
def test_api_rejects_virtual_host_evidence_outside_the_run_scope(
    tmp_path,
    monkeypatch,
    target: str,
    hostname: str,
) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'out-of-scope-vhost.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=_vhost_jsonl_result(target=target, value=hostname),
        )

    assert response.status_code == 400


def test_api_rejects_takeover_evidence_outside_the_run_scope(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    details = {
        'status': 'no-indicator',
        'dns': [
            {
                'resolver': '1.1.1.1',
                'cname_chain': [],
                'terminal_rcode': 'NOERROR',
            }
        ],
        'wildcard_dns': [],
        'http': [],
        'indicators': [],
        'error_types': [],
    }
    payload = _jsonl_result(
        target='example.test',
        finding_type='takeover',
        value='outside.example.net',
        finding_fields={'actions': ['takeover'], 'details': details},
        summary_fields={
            'action_executions': [
                {
                    'action': 'takeover',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'out-of-scope-takeover.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 400
    assert 'run target scope' in response.json()['detail']


def test_api_rejects_takeover_indicator_without_same_scheme_http_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    details = {
        'status': 'indicator',
        'dns': [
            {
                'resolver': '1.1.1.1',
                'cname_chain': ['bucket.s3.amazonaws.com'],
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
        'http': [{'scheme': 'http', 'status': 404}],
        'indicators': [
            {
                'classification': 'vulnerable-indicator',
                'service': 'AWS/S3',
                'rule_id': 'aws-s3',
                'rule_revision': 'takeover-rules-v1',
                'scheme': 'https',
                'matched': ['body:BucketName'],
            }
        ],
        'error_types': [],
    }
    payload = _jsonl_result(
        target='example.test',
        finding_type='takeover',
        value='bucket.example.test',
        finding_fields={'actions': ['takeover'], 'details': details},
        summary_fields={
            'action_executions': [
                {
                    'action': 'takeover',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'fabricated-takeover.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 400
    assert 'successful outcome for their matching scheme' in response.json()['detail']


def test_api_rejects_takeover_outcome_that_hides_nested_probe_failure(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    details = {
        'status': 'no-indicator',
        'dns': [
            {
                'resolver': '1.1.1.1',
                'cname_chain': [],
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
        'http': [{'scheme': 'https', 'error_type': 'TransportError'}],
        'indicators': [],
        'error_types': [],
    }
    payload = _jsonl_result(
        target='example.test',
        finding_type='takeover',
        value='bucket.example.test',
        finding_fields={'actions': ['takeover'], 'details': details},
        summary_fields={
            'action_executions': [
                {
                    'action': 'takeover',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'hidden-takeover-error.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 400
    assert 'candidate errors' in response.json()['detail']


def test_api_rejects_takeover_http_evidence_without_wildcard_controls(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    details = {
        'status': 'no-indicator',
        'dns': [
            {
                'resolver': '1.1.1.1',
                'cname_chain': ['bucket.s3.amazonaws.com'],
                'terminal_rcode': 'NOERROR',
            }
        ],
        'wildcard_dns': [],
        'http': [{'scheme': 'https', 'status': 404}],
        'indicators': [],
        'error_types': [],
    }
    payload = _jsonl_result(
        target='example.test',
        finding_type='takeover',
        value='bucket.example.test',
        finding_fields={'actions': ['takeover'], 'details': details},
        summary_fields={
            'action_executions': [
                {
                    'action': 'takeover',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'missing-takeover-control.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )

    assert response.status_code == 400
    assert 'wildcard control per resolver' in response.json()['detail']


def test_api_rejects_partial_virtual_host_observation(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    records = [json.loads(line) for line in _vhost_jsonl_result().splitlines()]
    records[1]['observations'][0].pop('control_body_sha256')
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'partial-vhost.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=''.join(json.dumps(record) + '\n' for record in records),
        )

    assert response.status_code == 400


@pytest.mark.parametrize(
    'mutation',
    ['impossible-phase', 'serialized-error', 'missing-confirmation', 'mismatched-confirmation'],
)
def test_api_rejects_unproven_virtual_host_observation(tmp_path, monkeypatch, mutation: str) -> None:
    from theHarvester.lib.api import api

    records = [json.loads(line) for line in _vhost_jsonl_result().splitlines()]
    observation = records[1]['observations'][0]
    if mutation == 'impossible-phase':
        observation['phase'] = 'connect'
    elif mutation == 'serialized-error':
        observation['error_type'] = None
    else:
        observation.update(
            status=200,
            context_body_sha256='b' * 64,
            control_body_sha256='b' * 64,
            distinct_signals=['body_sha256'],
        )
        if mutation == 'missing-confirmation':
            observation.pop('confirmation_body_sha256')
        else:
            observation['confirmation_body_sha256'] = 'b' * 64
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': f'{mutation}.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=''.join(json.dumps(record) + '\n' for record in records),
        )

    assert response.status_code == 400


def test_api_database_upload_preserves_grouped_virtual_host_observations(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_evidence import parse_jsonl_import
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.database import dispose_sqlite_databases

    source_database = tmp_path / 'source.sqlite'

    async def build_source_database() -> None:
        await RunStore(source_database).import_evidence(
            parse_jsonl_import(_vhost_jsonl_result().encode()),
            'vhost.jsonl',
        )
        await dispose_sqlite_databases()

    asyncio.run(build_source_database())
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'destination.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        uploaded = client.post(
            '/api/v1/runs/import-database',
            params={'filename': 'source.sqlite'},
            headers=headers,
            content=source_database.read_bytes(),
        )
        run_id = uploaded.json()['imported_run_ids'][0]
        detail = client.get(f'/api/v1/runs/{run_id}', headers=headers)
        exported = client.get(f'/api/v1/runs/{run_id}/export', headers=headers)

    assert uploaded.status_code == 201
    assert detail.status_code == 200
    assert detail.json()['results'][0]['observations'] == [
        _vhost_observation('https://192.0.2.8:443/'),
        _vhost_observation('https://192.0.2.9:443/'),
    ]
    assert json.loads(exported.text.splitlines()[1]) == detail.json()['results'][0]


def test_api_import_preserves_structured_shodan_host_details(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    details = {
        'organization': 'Example Transit',
        'services': [
            {'port': 53, 'transport': 'udp'},
            {
                'port': 443,
                'transport': 'tcp',
                'product': 'nginx',
                'tls': {
                    'subject_cn': '*.example.test',
                    'subject_alt_names': ['api.example.test'],
                    'sha256': '0123456789abcdef',
                },
            },
        ],
    }
    payload = _jsonl_result(
        finding_type='shodan-host',
        value='192.0.2.10',
        finding_fields={'actions': ['shodan'], 'details': details},
        summary_fields={
            'action_executions': [
                {
                    'action': 'shodan',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                }
            ]
        },
    )
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'shodan.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=payload,
        )
        assert imported.status_code == 201, imported.text
        detail = client.get(f'/api/v1/runs/{imported.json()["run_id"]}', headers={'X-API-Key': 'test-key'})

    assert detail.status_code == 200
    assert detail.json()['results'] == [
        {
            'type': 'shodan-host',
            'value': '192.0.2.10',
            'sources': [],
            'actions': ['shodan'],
            'details': details,
        }
    ]


def test_api_schema_exposes_typed_shodan_host_details() -> None:
    from theHarvester.lib.api.run_models import NormalizedResult

    schema = NormalizedResult.model_json_schema()

    assert schema['properties']['details']['anyOf'][0] == {'$ref': '#/$defs/ShodanHostDetailsResponse'}
    service = schema['$defs']['ShodanServiceResponse']
    assert service['properties']['port']['minimum'] == 1
    assert service['properties']['port']['maximum'] == 65535
    assert service['properties']['transport']['enum'] == ['tcp', 'udp']
    tls = schema['$defs']['ShodanTlsDetailsResponse']
    assert tls['properties']['subject_alt_names']['items'] == {'type': 'string'}


def test_api_schema_and_result_model_expose_typed_takeover_outcomes() -> None:
    from theHarvester.lib.api.run_models import NormalizedResult

    details = {
        'status': 'inconclusive',
        'dns': [
            {
                'resolver': '1.1.1.1',
                'cname_chain': [],
                'terminal_rcode': 'ERROR',
                'error_type': 'DNSTimeoutError',
            }
        ],
        'wildcard_dns': [],
        'http': [],
        'indicators': [],
        'error_types': ['DNSTimeoutError'],
    }

    result = NormalizedResult(
        type='takeover',
        value='uncertain.example.test',
        actions=['takeover'],
        details=details,
    )

    assert result.model_dump(exclude_none=True, exclude_defaults=True)['details'] == details
    schema = NormalizedResult.model_json_schema()
    assert {'$ref': '#/$defs/TakeoverDetailsResponse'} in schema['properties']['details']['anyOf']
    assert schema['$defs']['TakeoverDetailsResponse']['properties']['status']['enum'] == [
        'indicator',
        'no-indicator',
        'inconclusive',
    ]
    with pytest.raises(ValueError, match='canonical structured details'):
        NormalizedResult(
            type='takeover',
            value='Uncertain.Example.test.',
            actions=['takeover'],
            details=details,
        )


def test_api_projection_preserves_structured_takeover_details() -> None:
    from theHarvester.lib.api.run_models import NormalizedResult
    from theHarvester.lib.api.run_projection import normalized_results

    details = {
        'status': 'no-indicator',
        'dns': [{'resolver': '192.0.2.53', 'cname_chain': [], 'terminal_rcode': 'NOERROR'}],
        'wildcard_dns': [],
        'http': [],
        'indicators': [],
        'error_types': [],
    }
    projected = normalized_results(
        {
            'results': [
                {
                    'type': 'takeover',
                    'value': 'unused.example.test',
                    'sources': [],
                    'actions': ['takeover'],
                    'details': details,
                }
            ]
        }
    )

    assert projected[0]['details'] == details
    assert NormalizedResult.model_validate(projected[0]).details is not None


def test_api_evidence_rejects_redundant_shodan_host_fields() -> None:
    from fastapi import HTTPException

    from theHarvester.lib.api.run_evidence import validate_evidence

    evidence = {
        'target': 'example.test',
        'status': 'complete',
        'results': [
            {
                'type': 'shodan-host',
                'value': '192.0.2.10',
                'sources': [],
                'actions': ['shodan'],
                'details': {
                    'ip': '192.0.2.10',
                    'services': [{'port': 443, 'transport': 'tcp'}],
                },
            }
        ],
        'source_executions': [],
        'action_executions': [],
        'artifacts': [],
    }

    with pytest.raises(HTTPException, match='unsupported fields'):
        validate_evidence(evidence)


def test_api_database_upload_rejects_vhost_evidence_outside_its_stored_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_evidence import parse_jsonl_import
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.database import dispose_sqlite_databases

    source_database = tmp_path / 'source.sqlite'

    async def build_source_database() -> None:
        await RunStore(source_database).import_evidence(
            parse_jsonl_import(_vhost_jsonl_result().encode()),
            'vhost.jsonl',
        )
        await dispose_sqlite_databases()

    asyncio.run(build_source_database())
    with sqlite3.connect(source_database) as database:
        database.execute("UPDATE runs SET target = 'other.test'")
        database.commit()
        database.execute('PRAGMA wal_checkpoint(TRUNCATE)')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'destination.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs/import-database',
            params={'filename': 'out-of-scope.sqlite'},
            headers={'X-API-Key': 'test-key'},
            content=source_database.read_bytes(),
        )

    assert response.status_code == 400
    assert 'run target scope' in response.json()['detail']


def test_api_jsonl_round_trip_preserves_execution_outcomes_and_action_origins(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    payload = _jsonl_result(
        finding_type='hostname',
        value='api.example.test',
        finding_fields={'sources': ['crtsh', 'crtsh'], 'actions': ['dns-brute', 'dns-brute']},
        summary_fields={
            'evidence_status': 'partial',
            'source_executions': [
                {
                    'source': 'crtsh',
                    'status': 'completed',
                    'duration_ms': 1,
                    'result_count': 1,
                    'error_type': None,
                    'stop_reason': None,
                },
                {
                    'source': 'certspotter',
                    'status': 'rate-limited',
                    'duration_ms': 2,
                    'result_count': 0,
                    'error_type': None,
                    'stop_reason': 'http-429',
                },
            ],
            'action_executions': [
                {
                    'action': 'dns-brute',
                    'status': 'partial',
                    'duration_ms': 3,
                    'result_count': 1,
                    'error_type': 'TimeoutError',
                    'stop_reason': 'query-errors',
                }
            ],
        },
    )

    with TestClient(api.app, client=('127.0.0.18', 50000)) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'attributed.jsonl'},
            headers=headers,
            content=payload,
        )
        exported = client.get(f'/api/v1/runs/{imported.json()["run_id"]}/export', headers=headers)
        reimported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'attributed-round-trip.jsonl'},
            headers=headers,
            content=exported.content,
        )

    assert imported.status_code == 201
    assert exported.status_code == 200
    assert reimported.status_code == 201
    assert reimported.json()['evidence_status'] == 'partial'
    assert reimported.json()['source_executions'] == imported.json()['source_executions']
    assert reimported.json()['action_executions'] == imported.json()['action_executions']
    assert reimported.json()['results'] == [
        {
            'type': 'hostname',
            'value': 'api.example.test',
            'sources': ['crtsh'],
            'actions': ['dns-brute'],
        }
    ]


def test_api_rejects_non_string_jsonl_timestamps(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, client=('127.0.0.7', 50000)) as client:
        response = client.post(
            '/api/v1/runs/import',
            params={'filename': 'invalid.jsonl'},
            headers={'X-API-Key': 'test-key'},
            content=_jsonl_result(summary_fields={'completed_at': {'not': 'a timestamp'}}),
        )

    assert response.status_code == 400
    assert response.json()['detail'] == 'JSONL summary must contain an ISO-8601 UTC completed_at'


def test_api_rejects_invalid_jsonl_summary_identity_and_timestamps(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    cases = (
        ({'run_id': None}, None, 'JSONL summary must contain a UUID run_id'),
        ({}, 'run_id', 'JSONL summary must contain a UUID run_id'),
        ({'run_id': 'not-a-uuid'}, None, 'JSONL summary must contain a UUID run_id'),
        ({}, 'started_at', 'JSONL summary must contain an ISO-8601 UTC started_at'),
        ({}, 'completed_at', 'JSONL summary must contain an ISO-8601 UTC completed_at'),
        ({'started_at': 'not-a-time'}, None, 'JSONL summary must contain an ISO-8601 UTC started_at'),
        (
            {'completed_at': '2026-08-08T02:01:00+01:00'},
            None,
            'JSONL summary must contain an ISO-8601 UTC completed_at',
        ),
        (
            {'started_at': '2026-08-08T03:00:00Z', 'completed_at': '2026-08-08T02:00:00Z'},
            None,
            'JSONL summary completed_at must not be earlier than started_at',
        ),
    )

    for index, (updates, removed_field, detail) in enumerate(cases, start=8):
        records = [json.loads(line) for line in _jsonl_result().splitlines()]
        records[0].update(updates)
        if removed_field:
            records[0].pop(removed_field)
        content = ''.join(json.dumps(record) + '\n' for record in records)
        with TestClient(api.app, client=(f'127.0.0.{index}', 50000)) as client:
            response = client.post(
                '/api/v1/runs/import',
                params={'filename': 'invalid.jsonl'},
                headers={'X-API-Key': 'test-key'},
                content=content,
            )

        assert response.status_code == 400
        assert response.json()['detail'] == detail


def test_api_refuses_to_export_before_evidence_exists(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    run = asyncio.run(RunStore().create(RunRequest(target='example.test', sources=['crtsh'])))

    with TestClient(api.app) as client:
        response = client.get(f'/api/v1/runs/{run["run_id"]}/export', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 409
    assert response.json()['detail'] == 'No run evidence is available to export'
