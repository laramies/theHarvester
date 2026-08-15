from __future__ import annotations

import asyncio
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.harvestview_e2e


def write_jsonl_evidence(path: Path, evidence: dict[str, object]) -> None:
    results = evidence.get('results', [])
    assert isinstance(results, list)
    counts = Counter(str(result['type']) for result in results if isinstance(result, dict))
    summary = {
        'type': 'summary',
        'run_id': evidence['run_id'],
        'target': evidence['target'],
        'started_at': evidence['started_at'],
        'completed_at': evidence['completed_at'],
        'evidence_status': evidence['status'],
        'source_executions': evidence.get('source_executions', []),
        'action_executions': evidence.get('action_executions', []),
        'artifacts': evidence.get('artifacts', []),
        'result_count': len(results),
        'counts': dict(sorted(counts.items())),
    }
    records = [
        summary,
        *[
            {**result, 'sources': result.get('sources', []), 'actions': result.get('actions', [])}
            for result in results
            if isinstance(result, dict)
        ],
    ]
    path.write_text(''.join(json.dumps(record, sort_keys=True) + '\n' for record in records), encoding='utf-8')


def record_api_statuses(page: Page, server_url: str) -> dict[str, int]:
    api_statuses: dict[str, int] = {}

    def record_response(response) -> None:
        if response.url.startswith(f'{server_url}/api/v1/'):
            api_statuses[response.url.removeprefix(server_url)] = response.status

    page.on('response', record_response)
    return api_statuses


def test_fresh_browser_session_authenticates_through_harvestview(
    harvestview_server_url: str,
    page: Page,
) -> None:
    api_statuses = record_api_statuses(page, harvestview_server_url)
    page.goto(f'{harvestview_server_url}/')

    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()
    assert api_statuses['/api/v1/sources'] == 200
    assert api_statuses['/api/v1/runs'] == 200
    expect(page.get_by_text('Invalid API key')).to_have_count(0)


def test_browser_session_stays_authenticated_after_server_restart(
    harvestview_server,
    page: Page,
) -> None:
    page.goto(f'{harvestview_server.url}/')
    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()

    harvestview_server.restart()
    page.reload()

    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()
    expect(page.get_by_text('Invalid API key')).to_have_count(0)


@pytest.mark.parametrize('viewport', [{'width': 1440, 'height': 900}, {'width': 390, 'height': 844}])
def test_versioned_assets_and_tooltips_work_at_supported_viewports(
    harvestview_server_url: str,
    page: Page,
    viewport: dict[str, int],
) -> None:
    page.set_viewport_size(viewport)
    page.goto(f'{harvestview_server_url}/')

    stylesheet = page.locator('link[href*="/static/harvestview/app.css"]')
    script = page.locator('script[src*="/static/harvestview/app.js"]')
    assert '?v=' in (stylesheet.get_attribute('href') or '')
    assert '?v=' in (script.get_attribute('src') or '')
    assert '{{' not in (stylesheet.get_attribute('href') or '')
    assert '{{' not in (script.get_attribute('src') or '')

    page.get_by_role('button', name='Start enumeration').first.click()
    tooltip = page.get_by_role('button', name='Explain discovery sources')
    tooltip.hover()
    page.wait_for_function(
        "node => getComputedStyle(node, '::after').opacity === '1'",
        arg=tooltip.element_handle(),
    )
    tooltip_content = tooltip.evaluate("node => getComputedStyle(node, '::after').content")

    assert 'Credential warnings identify sources that cannot start' in tooltip_content
    assert 'Credential warnings identify sources that cannot start' in tooltip.get_attribute('aria-description')
    assert tooltip.bounding_box()['width'] >= 44
    assert tooltip.bounding_box()['height'] >= 44
    assert page.locator('#submit-run-button').evaluate(
        """button => {
          const buttonBox = button.getBoundingClientRect();
          const dialogBox = button.closest('dialog').getBoundingClientRect();
          return buttonBox.top >= dialogBox.top && buttonBox.bottom <= dialogBox.bottom && buttonBox.bottom <= innerHeight;
        }"""
    )
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')


def test_mobile_source_picker_avoids_nested_scroll_and_blocks_unconfigured_sources(
    harvestview_server_url: str,
    page: Page,
) -> None:
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Start enumeration').first.click()

    assert page.locator('#source-groups').evaluate(
        'node => ({maxHeight: getComputedStyle(node).maxHeight, overflowY: getComputedStyle(node).overflowY})'
    ) == {'maxHeight': 'none', 'overflowY': 'visible'}
    p0_group = page.locator('[data-activity="P0"]')
    p0_group.locator('summary').click()
    expect(p0_group).not_to_have_attribute('open', '')
    expect(page.locator('[data-activity="P1"] summary')).to_be_visible()

    censys = page.locator('.source-choice').filter(has_text='censys')
    expect(censys.locator('input')).to_be_disabled()
    expect(censys).to_contain_text('Needs configuration')
    crtsh = page.locator('.source-choice').filter(has_text='crtsh')
    expect(crtsh.locator('input')).to_be_enabled()
    expect(crtsh).to_contain_text('Ready')
    expect(page.locator('#source-selection-summary')).to_contain_text('Selected 1 ready source')
    p0_group.locator('summary').click()
    crtsh.locator('input').uncheck()
    expect(page.locator('#source-selection-summary')).to_contain_text('Selected 0 ready sources')


def test_disabled_worker_rejects_submission_without_creating_a_run(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Start enumeration').first.click()
    page.locator('#run-target').fill('example.com')

    with page.expect_response(
        lambda response: response.url == f'{harvestview_server_url}/api/v1/runs' and response.request.method == 'POST'
    ) as submission:
        page.locator('#submit-run-button').click()

    assert submission.value.status == 503
    expect(page.locator('#new-run-error')).to_have_text('theHarvester execution worker is disabled')
    history = page.context.request.get(f'{harvestview_server_url}/api/v1/runs')
    assert history.status == 200
    assert history.json() == []


def test_harvestview_can_submit_overridable_execution_controls(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
    tmp_path: Path,
) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    captured: dict[str, object] = {}

    def capture_submission(route: Route) -> None:
        if route.request.method != 'POST':
            route.continue_()
            return
        captured.update(route.request.post_data_json)
        route.fulfill(status=503, json={'detail': 'Controls captured'})

    page.route(f'{harvestview_server_url}/api/v1/runs', capture_submission)
    page.goto(f'{harvestview_server_url}/')
    start_button = page.get_by_role('button', name='Start enumeration').first
    expect(start_button).to_be_enabled()
    page.set_default_timeout(2_000)
    start_button.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#run-target').fill('example.com')
    page.get_by_text('Advanced execution controls', exact=True).click()
    page.locator('#run-start').fill('25')
    page.locator('#source-workers').fill('7')
    page.locator('#run-deadline').fill('86400')
    page.locator('[name="proxies"]').check()
    page.locator('[name="shodan"]').check()
    page.locator('[name="routeviews"]').check()
    page.locator('[name="dns_lookup"]').check()
    page.locator('[name="takeover"]').check()
    page.locator('[name="api_scan"]').check()
    page.locator('#api-scan-paths').fill('/api/v2\n/health')
    page.locator('#dns-recursive-depth').fill('3')
    page.locator('#dns-recursive-query-limit').fill('1234')
    page.locator('#dns-recursive-runtime-seconds').fill('12.5')
    resolver_file = tmp_path / 'resolvers.txt'
    resolver_file.write_text('192.0.2.53\n198.51.100.53\n203.0.113.53\n', encoding='utf-8')
    page.locator('#dns-resolver-file').set_input_files(resolver_file)
    expect(page.locator('#dns-resolvers')).to_have_value('192.0.2.53,198.51.100.53,203.0.113.53')

    expect(page.locator('#activity-summary')).to_have_text('P0 selected · P1 selected · P2 selected')
    page.locator('[data-activity="P0"] input[value="crtsh"]').check()
    page.locator('#submit-run-button').click()
    expect(page.locator('#new-run-error')).to_have_text('Controls captured')

    assert captured == {
        'target': 'example.com',
        'sources': ['crtsh'],
        'limit': 500,
        'start': 25,
        'source_workers': 7,
        'deadline_seconds': 86_400,
        'proxies': True,
        'no_hosts': False,
        'dns_lookup': True,
        'dns_resolve': False,
        'dns_resolvers': ['192.0.2.53', '198.51.100.53', '203.0.113.53'],
        'dns_recursive_depth': 3,
        'dns_recursive_query_limit': 1_234,
        'dns_recursive_runtime_seconds': 12.5,
        'dns_brute': False,
        'shodan': True,
        'routeviews': True,
        'screenshot': False,
        'takeover': True,
        'api_scan': True,
        'api_scan_paths': ['/api/v2', '/health'],
        'vhost': False,
        'vhost_endpoint': '',
        'vhost_candidates': [],
        'vhost_request_limit': 100,
        'vhost_runtime_seconds': 30,
        'vhost_timeout_seconds': 5,
        'vhost_concurrency': 5,
        'vhost_insecure': False,
    }


def test_harvestview_submits_hostname_exclusion(harvestview_server_url: str, page: Page, browser_failures) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    captured: dict[str, object] = {}

    def capture_submission(route: Route) -> None:
        if route.request.method != 'POST':
            route.continue_()
            return
        captured.update(route.request.post_data_json)
        route.fulfill(status=503, json={'detail': 'Hostname exclusion captured'})

    page.route(f'{harvestview_server_url}/api/v1/runs', capture_submission)
    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Start enumeration').first.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#run-target').fill('example.com')
    page.get_by_text('Advanced execution controls', exact=True).click()
    page.locator('[name="no_hosts"]').check()
    page.locator('[data-activity="P0"] input[value="apis-guru"]').check()
    page.locator('#submit-run-button').click()

    expect(page.locator('#new-run-error')).to_have_text('Hostname exclusion captured')
    assert captured['sources'] == ['apis-guru']
    assert captured['no_hosts'] is True


def test_harvestview_requires_complete_inputs_for_a_vhost_only_run(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    captured: dict[str, object] = {}

    def capture_submission(route: Route) -> None:
        if route.request.method != 'POST':
            route.continue_()
            return
        captured.update(route.request.post_data_json)
        route.fulfill(status=503, json={'detail': 'Virtual-host controls captured'})

    page.route(f'{harvestview_server_url}/api/v1/runs', capture_submission)
    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Start enumeration').first.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#run-target').fill('example.com')
    page.get_by_text('P2 · Virtual-host discovery', exact=True).click()
    page.locator('#vhost-endpoint').fill('https://192.0.2.10:443/')

    expect(page.locator('#activity-summary')).to_have_text('P0 off · P1 off · P2 selected')
    page.locator('#submit-run-button').click()
    expect(page.locator('#new-run-error')).to_have_text(
        'Virtual-host discovery without sources requires both a literal-IP endpoint and at least one candidate hostname.'
    )
    assert captured == {}

    page.locator('#vhost-candidates').fill('admin.example.com\npreview.example.com')
    page.locator('#submit-run-button').click()
    expect(page.locator('#new-run-error')).to_have_text('Virtual-host controls captured')

    assert captured['sources'] == []
    assert captured['dns_resolvers']
    assert captured['takeover'] is False
    assert captured['api_scan_paths'] == []
    assert captured['vhost'] is True
    assert captured['vhost_endpoint'] == 'https://192.0.2.10:443/'
    assert captured['vhost_candidates'] == ['admin.example.com', 'preview.example.com']
    assert captured['vhost_request_limit'] == 100
    assert captured['vhost_runtime_seconds'] == 30
    assert captured['vhost_timeout_seconds'] == 5
    assert captured['vhost_concurrency'] == 5
    assert captured['vhost_insecure'] is False


def test_harvestview_submits_a_target_only_api_scan(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    captured: dict[str, object] = {}

    def capture_submission(route: Route) -> None:
        if route.request.method != 'POST':
            route.continue_()
            return
        captured.update(route.request.post_data_json)
        route.fulfill(status=503, json={'detail': 'Target-only action captured'})

    page.route(f'{harvestview_server_url}/api/v1/runs', capture_submission)
    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Start enumeration').first.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#run-target').fill('api.example.test')
    page.locator('[name="api_scan"]').check()
    page.get_by_text('Advanced execution controls', exact=True).click()
    page.locator('#api-scan-paths').fill('/api/v2\n/health')
    page.locator('#submit-run-button').click()

    expect(page.locator('#new-run-error')).to_have_text('Target-only action captured')
    assert captured['sources'] == []
    assert captured['api_scan'] is True
    assert captured['api_scan_paths'] == ['/api/v2', '/health']


def test_harvestview_renders_grouped_virtual_host_observations(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'vhost-run',
        'target': 'example.com',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': '2026-08-05T12:00:05+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 2,
        'activities': ['P0', 'P2'],
        'sources': ['crtsh'],
        'request': {
            'sources': ['crtsh'],
            'limit': 25,
            'deadline_seconds': 300,
            'vhost': True,
            'vhost_endpoint': '',
            'vhost_candidates': [],
            'vhost_request_limit': 100,
            'vhost_runtime_seconds': 30,
            'vhost_timeout_seconds': 5,
            'vhost_concurrency': 5,
            'vhost_insecure': False,
        },
        'source_executions': [],
        'action_executions': [
            {'action': 'vhost', 'status': 'completed', 'result_count': 1, 'duration_ms': 125},
        ],
        'results': [
            {
                'type': 'hostname',
                'value': 'admin.example.com',
                'sources': [],
                'actions': ['vhost'],
                'observations': [
                    {
                        'endpoint': 'https://192.0.2.10:443/',
                        'phase': 'body',
                        'status': 200,
                        'location': None,
                        'context_status': 200,
                        'control_status': 200,
                        'confirmation_body_sha256': 'a' * 64,
                        'tls_verified': True,
                        'distinct_signals': ['body_sha256'],
                    },
                    {
                        'endpoint': 'http://198.51.100.20:80/',
                        'phase': 'body',
                        'status': 302,
                        'location': '/login',
                        'context_status': 404,
                        'control_status': 404,
                        'confirmation_body_sha256': None,
                        'tls_verified': None,
                        'distinct_signals': ['status', 'location'],
                    },
                ],
            },
            {
                'type': 'hostname',
                'value': 'www.example.com',
                'sources': ['crtsh'],
                'actions': [],
            },
        ],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/vhost-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    expect(page.get_by_role('button', name='Hostnames 2')).to_be_enabled()
    expect(page.get_by_role('button', name='Virtual hosts 1')).to_have_count(0)
    expect(page.locator('#route-count')).to_have_text('2')
    expect(page.locator('#results-summary')).to_have_text('2 normalized results across 1 route.')
    result_row = page.locator('.tabulator-row').first
    expect(result_row).to_contain_text('admin.example.com')
    expect(result_row).to_contain_text(
        'https://192.0.2.10:443/ · HTTP 200 · body_sha256 · IP HTTP 200 · unknown HTTP 200 · body confirmed · TLS verified'
    )
    expect(result_row).to_contain_text(
        'http://198.51.100.20:80/ · HTTP 302 → /login · status, location · IP HTTP 404 · unknown HTTP 404'
    )
    expect(result_row).to_contain_text('vhost')
    expect(page.get_by_role('button', name='Take screenshot of admin.example.com (P2)')).to_be_visible()
    expect(page.get_by_role('button', name='DNS brute force admin.example.com (P1)')).to_be_visible()


def test_harvestview_renders_sourced_asn_organization_attribution(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'asn-attribution-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-12T12:00:00+00:00',
        'started_at': '2026-08-12T12:00:01+00:00',
        'completed_at': '2026-08-12T12:00:05+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 2,
        'activities': ['P0'],
        'sources': ['urlscan'],
        'request': {'sources': ['urlscan'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [
            {'source': 'urlscan', 'status': 'completed', 'result_count': 2, 'duration_ms': 125},
        ],
        'action_executions': [],
        'results': [
            {
                'type': 'asn',
                'value': 'AS64500',
                'sources': ['urlscan'],
                'actions': [],
                'observations': [
                    {
                        'type': 'organization-attribution',
                        'producer_kind': 'source',
                        'producer': 'urlscan',
                        'organization_label': 'Example Transit',
                        'subject': {'type': 'hostname', 'value': 'api.example.test'},
                        'collected_at': '2026-08-12T12:00:03Z',
                    }
                ],
            },
            {
                'type': 'hostname',
                'value': 'api.example.test',
                'sources': ['urlscan'],
                'actions': [],
            },
        ],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/asn-attribution-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    page.get_by_role('button', name='ASNs 1').click()
    result_row = page.locator('.tabulator-row').first
    expect(result_row).to_contain_text('AS64500')
    expect(result_row).to_contain_text('Example Transit · source:urlscan · hostname:api.example.test')


def test_harvestview_summarizes_routeviews_prefix_evidence(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'routeviews-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-12T12:00:00+00:00',
        'started_at': '2026-08-12T12:00:01+00:00',
        'completed_at': '2026-08-12T12:00:05+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 2,
        'activities': ['P0'],
        'sources': ['urlscan'],
        'request': {'sources': ['urlscan'], 'limit': 25, 'deadline_seconds': 300, 'routeviews': True},
        'source_executions': [],
        'action_executions': [
            {'action': 'routeviews', 'status': 'completed', 'result_count': 2, 'duration_ms': 125},
        ],
        'results': [
            {
                'type': 'asn',
                'value': 'AS64500',
                'sources': [],
                'actions': ['routeviews'],
            },
            {
                'type': 'prefix',
                'value': '192.0.2.0/24',
                'scope': 'external-relationship',
                'sources': [],
                'actions': ['routeviews'],
                'observations': [
                    {
                        'type': 'observed-origin',
                        'action': 'routeviews',
                        'origin_asn': 'AS64500',
                        'collected_at': '2026-08-12T12:00:03Z',
                    },
                    {
                        'type': 'rpki-validation',
                        'action': 'routeviews',
                        'origin_asn': 'AS64500',
                        'state': 'valid',
                        'observed_at': '2026-08-12T11:59:00Z',
                        'collected_at': '2026-08-12T12:00:03Z',
                    },
                    {
                        'type': 'bgp-route',
                        'action': 'routeviews',
                        'origin_asn': 'AS64500',
                        'collector': 'route-views.example',
                        'peer_asn': 'AS64496',
                        'peer_address': '198.51.100.1',
                        'as_path': '64496 64500',
                        'communities': '64500:1',
                        'observed_at': '2026-08-12T11:59:00Z',
                        'collected_at': '2026-08-12T12:00:03Z',
                    },
                ],
            },
        ],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/routeviews-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    page.get_by_role('button', name='Network prefixes 1').click()
    expect(page.locator('#request-options')).to_contain_text('RouteViews enrichmentSelected')
    result_row = page.locator('.tabulator-row').first
    expect(result_row).to_contain_text('192.0.2.0/24')
    expect(result_row).to_contain_text('AS64500 · RPKI valid')
    expect(result_row.get_by_text('1 BGP route observation')).to_be_visible()
    result_row.get_by_text('1 BGP route observation').click()
    expect(result_row).to_contain_text('route-views.example · peer AS64496 (198.51.100.1)')
    expect(result_row).to_contain_text('path 64496 64500 · communities 64500:1')


def test_hostname_actions_queue_isolated_runs(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    run = {
        'run_id': 'parent-run',
        'target': 'example.com',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': '2026-08-05T12:00:05+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 1,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {
            'sources': ['crtsh'],
            'limit': 25,
            'deadline_seconds': 300,
            'dns_resolvers': ['192.0.2.53'],
        },
        'source_executions': [],
        'action_executions': [
            {
                'action': 'dns-brute',
                'status': 'failed',
                'result_count': 0,
                'duration_ms': 125,
                'error_type': 'TimeoutError',
                'stop_reason': 'query-errors',
            }
        ],
        'results': [{'type': 'hostname', 'value': 'api.example.com'}],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    submissions: list[dict[str, object]] = []

    def route_runs(route: Route) -> None:
        if route.request.method == 'POST':
            submission = route.request.post_data_json
            submissions.append(submission)
            detail = 'Screenshot captured' if submission.get('screenshot') else 'DNS brute captured'
            route.fulfill(status=503, json={'detail': detail})
        else:
            route.fulfill(json=[run])

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.route(f'{harvestview_server_url}/api/v1/runs/parent-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    expect(page.get_by_role('button', name='Hostnames 1')).to_be_enabled()

    page.locator('#provider-details summary').click()
    expect(page.locator('#provider-title')).to_have_text('Execution outcomes')
    action_row = page.locator('#provider-body tr').filter(has_text='dns-brute')
    expect(action_row).to_contain_text('Action')
    expect(action_row).to_contain_text('failed')
    expect(action_row).to_contain_text('TimeoutError')

    page.get_by_role('button', name='Take screenshot of api.example.com (P2)').click()
    expect(page.locator('#toast')).to_contain_text('Screenshot captured')
    page.get_by_role('button', name='DNS brute force api.example.com (P1)').click()
    expect(page.locator('#toast')).to_contain_text('DNS brute captured')

    assert submissions == [
        {'target': 'api.example.com', 'sources': [], 'screenshot': True},
        {
            'target': 'api.example.com',
            'sources': [],
            'dns_brute': True,
            'dns_resolvers': ['192.0.2.53'],
        },
    ]


def test_accepted_result_action_is_not_reported_as_failed_when_refresh_fails(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('GET', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    run = {
        'run_id': 'parent-run',
        'target': 'example.com',
        'status': 'running',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': None,
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 1,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [],
        'action_executions': [],
        'results': [{'type': 'hostname', 'value': 'api.example.com'}],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    list_calls = 0
    post_calls = 0
    cancelled_ids: list[str] = []

    def route_runs(route: Route) -> None:
        nonlocal list_calls, post_calls
        if route.request.method == 'POST':
            post_calls += 1
            route.fulfill(status=201, json={'run_id': 'queued-action', 'target': 'api.example.com', 'status': 'queued'})
            return
        list_calls += 1
        if list_calls == 1:
            route.fulfill(json=[run])
        elif list_calls == 2:
            route.fulfill(status=503, json={'detail': 'Refresh unavailable'})
        else:
            route.fulfill(json=[{**run, 'status': 'cancelled', 'completed_at': '2026-08-05T12:00:06+00:00'}])

    def route_cancel(route: Route, run_id: str) -> None:
        cancelled_ids.append(run_id)
        route.fulfill(json={**run, 'status': 'cancelled', 'completed_at': '2026-08-05T12:00:06+00:00'})

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.route(
        f'{harvestview_server_url}/api/v1/runs/parent-run/cancel',
        lambda route: route_cancel(route, 'parent-run'),
    )
    page.route(
        f'{harvestview_server_url}/api/v1/runs/queued-action/cancel',
        lambda route: route_cancel(route, 'queued-action'),
    )
    page.route(f'{harvestview_server_url}/api/v1/runs/parent-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    page.get_by_role('button', name='Take screenshot of api.example.com (P2)').click()

    expect(page.locator('#toast')).to_contain_text('was queued, but the run view could not refresh')
    expect(page.locator('#toast')).to_contain_text('Do not submit it again')
    expect(page.locator('#detail-run-id')).to_have_text('parent-run')
    page.locator('#cancel-run-button').click()
    expect(page.locator('#toast')).to_have_text('Queued enumeration cancelled.')
    assert post_calls == 1
    assert cancelled_ids == ['parent-run']


def test_accepted_cancellation_is_not_reported_as_failed_when_history_refresh_fails(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('GET', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    run = {
        'run_id': 'running-run',
        'target': 'example.com',
        'status': 'running',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': None,
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [],
        'action_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    list_calls = 0
    cancel_calls = 0

    def route_runs(route: Route) -> None:
        nonlocal list_calls
        list_calls += 1
        if list_calls == 1:
            route.fulfill(json=[run])
        else:
            route.fulfill(status=503, json={'detail': 'Refresh unavailable'})

    def route_cancel(route: Route) -> None:
        nonlocal cancel_calls
        cancel_calls += 1
        route.fulfill(json={**run, 'status': 'cancelling', 'cancellation_requested_at': '2026-08-05T12:00:02+00:00'})

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.route(f'{harvestview_server_url}/api/v1/runs/running-run/cancel', route_cancel)
    page.route(f'{harvestview_server_url}/api/v1/runs/running-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    page.locator('#cancel-run-button').click()

    expect(page.locator('#toast')).to_contain_text('Cancellation was accepted, but run history could not refresh')
    expect(page.locator('#toast')).to_contain_text('Do not request it again')
    assert cancel_calls == 1


def test_harvestview_can_select_sources_by_result_capability(harvestview_server_url: str, page: Page) -> None:
    page.goto(f'{harvestview_server_url}/')
    catalog = page.context.request.get(f'{harvestview_server_url}/api/v1/sources').json()
    expected = {source['name'] for source in catalog['sources'] if source['ready'] and 'ips' in source['capabilities']}

    page.get_by_role('button', name='Start enumeration').first.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#source-capability').select_option('ips')
    page.get_by_role('button', name='Add sources').click()

    selected = set(page.locator('#source-groups input:checked').evaluate_all('(inputs) => inputs.map(input => input.value)'))
    assert selected == expected


def test_polling_recovers_after_one_transient_refresh_failure(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('GET', 503, '/api/v1/runs/retry-run')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    run = {
        'run_id': 'retry-run',
        'target': 'example.com',
        'status': 'running',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': None,
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    detail_calls = 0

    def route_runs(route: Route) -> None:
        route.fulfill(json=[run])

    def route_detail(route: Route) -> None:
        nonlocal detail_calls
        detail_calls += 1
        if detail_calls == 2:
            route.fulfill(status=503, json={'detail': 'Temporary refresh failure'})
        else:
            completed = detail_calls >= 3
            route.fulfill(
                json={
                    **run,
                    'status': 'completed' if completed else 'running',
                    'completed_at': '2026-08-05T12:00:05+00:00' if completed else None,
                    'evidence_status': 'complete' if completed else 'partial',
                }
            )

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.route(f'{harvestview_server_url}/api/v1/runs/retry-run', route_detail)
    page.goto(f'{harvestview_server_url}/')

    expect(page.locator('#status-chips')).to_contain_text('completed', timeout=7_000)
    assert detail_calls >= 3


def test_workspace_startup_failure_has_an_inline_retry(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_response('GET', 503, '/api/v1/sources')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )
    source_calls = 0

    def fail_once(route: Route) -> None:
        nonlocal source_calls
        source_calls += 1
        if source_calls == 1:
            route.fulfill(status=503, json={'detail': 'Temporary startup failure'})
        else:
            route.continue_()

    page.route(f'{harvestview_server_url}/api/v1/sources', fail_once)
    page.goto(f'{harvestview_server_url}/')
    page.set_default_timeout(3_000)

    expect(page.locator('#workspace-error')).to_be_visible()
    expect(page.locator('#workspace-error-message')).to_have_text('Temporary startup failure')
    page.locator('#retry-workspace-button').click()

    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()
    assert source_calls == 2


def test_unchanged_poll_keeps_result_table_filters(harvestview_server_url: str, page: Page) -> None:
    run = {
        'run_id': 'stable-run',
        'target': 'example.com',
        'status': 'running',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': None,
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 1,
        'activities': ['P0', 'P2'],
        'sources': ['crtsh'],
        'request': {
            'sources': ['crtsh'],
            'limit': 25,
            'deadline_seconds': 300,
            'proxies': True,
            'dns_lookup': True,
            'takeover': True,
        },
        'source_executions': [],
        'results': [{'type': 'hostname', 'value': 'api.example.com'}],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/stable-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')
    expect(page.locator('#request-options')).to_contain_text('Proxy transportSelected')
    expect(page.locator('#request-options')).to_contain_text('DNS lookup (/24 reverse expansion)Selected')
    expect(page.locator('#request-options')).to_contain_text('Takeover transportConfigured proxy')
    value_filter = page.locator('.tabulator-col[tabulator-field="value"] .tabulator-header-filter input')
    value_filter.fill('api')

    page.wait_for_timeout(1_600)

    expect(value_filter).to_have_value('api')


@pytest.mark.parametrize('initial_detail_status', ['queued', 'running'])
def test_submission_notification_matches_the_loaded_lifecycle(
    harvestview_server_url: str,
    page: Page,
    initial_detail_status: str,
) -> None:
    page.goto(f'{harvestview_server_url}/')
    queued_run = {
        'run_id': 'toast-run',
        'target': 'example.com',
        'status': 'queued',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': None,
        'completed_at': None,
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    detail_status = initial_detail_status

    def route_runs(route: Route) -> None:
        if route.request.method == 'POST':
            route.fulfill(status=201, json=queued_run)
        else:
            route.fulfill(json=[{**queued_run, 'status': 'running', 'started_at': '2026-08-05T12:00:01+00:00'}])

    def route_detail(route: Route) -> None:
        if detail_status == 'queued':
            run = queued_run
        elif detail_status == 'running':
            run = {
                **queued_run,
                'status': 'running',
                'started_at': '2026-08-05T12:00:01+00:00',
            }
        else:
            run = {
                **queued_run,
                'status': 'cancelling',
                'started_at': '2026-08-05T12:00:01+00:00',
                'cancellation_requested_at': '2026-08-05T12:00:02+00:00',
            }
        route.fulfill(json=run)

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.route(f'{harvestview_server_url}/api/v1/runs/toast-run', route_detail)
    page.get_by_role('button', name='Start enumeration').first.click()
    page.locator('#run-target').fill('example.com')
    page.locator('#run-limit').fill('25')
    page.locator('#run-deadline').fill('300')
    page.locator('#submit-run-button').click()

    if initial_detail_status == 'queued':
        expect(page.locator('#toast')).to_have_text('Enumeration for example.com is queued.')
        detail_status = 'running'
    expect(page.locator('#status-chips')).to_contain_text('running')
    expect(page.locator('#submit-run-button')).to_be_enabled()
    expect(page.locator('#toast')).to_be_hidden(timeout=2500)
    detail_status = 'cancelling'
    expect(page.locator('#lifecycle-track strong')).to_contain_text(['Cancellation requested'])


@pytest.mark.parametrize(
    ('terminal_status', 'title', 'copy'),
    [
        ('cancelled', 'Enumeration cancelled', 'The enumeration was cancelled.'),
        ('failed', 'Enumeration failed', 'Provider process exited.'),
    ],
)
def test_empty_terminal_run_explains_its_lifecycle(
    harvestview_server_url: str,
    page: Page,
    terminal_status: str,
    title: str,
    copy: str,
) -> None:
    run = {
        'run_id': f'{terminal_status}-run',
        'target': 'example.com',
        'status': terminal_status,
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': '2026-08-05T12:00:02+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': 'Provider process exited.' if terminal_status == 'failed' else None,
    }
    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/{run["run_id"]}', lambda route: route.fulfill(json=run))

    page.goto(f'{harvestview_server_url}/')

    expect(page.locator('#results-empty-title')).to_have_text(title)
    expect(page.locator('#results-empty-copy')).to_contain_text(copy)
    expect(page.locator('#results-empty-copy')).to_contain_text('The retained evidence record is partial.')


def test_completed_empty_import_explains_terminal_outcome(
    harvestview_server_url: str,
    page: Page,
    tmp_path: Path,
) -> None:
    evidence_file = tmp_path / 'empty-run.jsonl'
    write_jsonl_evidence(
        evidence_file,
        {
            'run_id': '4ce79bb1-91a1-4456-8589-e5d82b55f2b4',
            'target': 'example.com',
            'started_at': '2026-08-05T12:00:00+00:00',
            'completed_at': '2026-08-05T12:00:25+00:00',
            'status': 'complete',
            'source_executions': [
                {'source': 'crtsh', 'status': 'completed', 'result_count': 0, 'duration_ms': 25000},
            ],
            'results': [],
        },
    )

    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(evidence_file)
    page.locator('#submit-import-button').click()

    expect(page.locator('#results-empty-title')).to_have_text('Enumeration completed')
    expect(page.locator('#results-summary')).to_have_text(
        '0 normalized results · 1 completed (1 zero-result) / 0 partial / 0 skipped / 0 failed.'
    )
    expect(page.locator('#results-empty-copy')).to_have_text(
        'crtsh returned no normalized evidence. The retained evidence record is complete.'
    )
    expect(page.locator('#lifecycle-track strong')).to_have_text(['Submitted', 'Started', 'Completed'])
    expect(page.get_by_role('button', name='All JSONL')).to_be_enabled()
    with page.expect_download() as jsonl_download:
        page.get_by_role('button', name='All JSONL').click()
    exported_records = [json.loads(line) for line in Path(jsonl_download.value.path()).read_text(encoding='utf-8').splitlines()]
    assert len(exported_records) == 1
    assert exported_records[0]['evidence_status'] == 'complete'
    assert exported_records[0]['result_count'] == 0
    assert exported_records[0]['source_executions'][0]['status'] == 'completed'


def test_harvestview_imports_completed_runs_from_sqlite(
    harvestview_server_url: str,
    page: Page,
    tmp_path: Path,
) -> None:
    from theHarvester.lib.completed_result import CompletedResult
    from theHarvester.lib.database import ResultStore, dispose_sqlite_databases

    database = tmp_path / 'completed-runs.sqlite'
    now = datetime.now(UTC)
    completed = CompletedResult.finish(
        target='sqlite.example.test',
        started_at=now,
        completed_at=now,
        groups={'hostname': ['api.sqlite.example.test']},
    )

    async def prepare_database() -> None:
        store = ResultStore(database)
        await store.initialize()
        await store.save_run(completed)
        await dispose_sqlite_databases()

    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(lambda: asyncio.run(prepare_database())).result()

    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(database)
    page.locator('#submit-import-button').click()

    expect(page.locator('#detail-target')).to_have_text('sqlite.example.test')
    expect(page.locator('#run-count')).to_have_text('1')
    expect(page.locator('#toast')).to_have_text('Imported 1 run from completed-runs.sqlite; 0 already present.')
    expect(page.get_by_role('button', name='Hostnames 1')).to_be_enabled()


def test_harvestview_can_import_and_analyze_fixture_evidence_through_the_real_ui(
    harvestview_server_url: str,
    page: Page,
    tmp_path: Path,
) -> None:
    page.set_viewport_size({'width': 1440, 'height': 900})
    page.context.grant_permissions(['clipboard-read', 'clipboard-write'], origin=harvestview_server_url)
    page.goto(f'{harvestview_server_url}/')
    catalog = page.context.request.get(f'{harvestview_server_url}/api/v1/sources').json()
    passive_sources = [source for source in catalog['sources'] if source['activity'] == 'P0']
    credentialed = [source for source in passive_sources if source['credentials']]
    uncredentialed = [source for source in passive_sources if not source['credentials']]
    ordered_sources = uncredentialed[:23] + credentialed[:2] + uncredentialed[23:] + credentialed[2:]
    assert len(ordered_sources) == len(passive_sources)
    assert ordered_sources[23]['credentials']
    assert ordered_sources[24]['credentials']

    evidence = {
        'run_id': '7bb74ee1-c81c-4ccd-8ec7-e8e496490f53',
        'target': 'example.com',
        'started_at': '2026-08-04T12:00:01+00:00',
        'completed_at': '2026-08-04T12:03:21+00:00',
        'status': 'partial',
        'source_executions': [
            {
                'source': source['name'],
                'status': 'completed' if index < 23 else 'skipped',
                'result_count': 1 if index < 3 else 0,
                'duration_ms': index + 1,
                **({'error_type': 'SourceDidNotStart'} if index >= 23 else {}),
                **({'stop_reason': 'missing-credentials'} if index == 23 else {}),
            }
            for index, source in enumerate(ordered_sources)
        ],
        'results': [
            {
                'type': result_type,
                'value': (
                    '192.0.2.10' if result_type == 'ip' else 'AS64500' if result_type == 'asn' else f'{result_type}.example.com'
                ),
                'sources': [ordered_sources[index]['name']] if index < 3 else [],
            }
            for index, result_type in enumerate(('hostname', 'ip', 'asn', 'email', 'url', 'framework', 'person', 'language'))
        ]
        + [
            {
                'type': 'ip',
                'value': '198.51.100.10',
            }
        ],
    }
    evidence_file = tmp_path / 'broad-run.jsonl'
    write_jsonl_evidence(evidence_file, evidence)

    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(evidence_file)
    page.locator('#submit-import-button').click()

    expect(page.locator('#provider-outcome-summary')).to_have_text(
        f'23 completed (20 zero-result) / 0 partial / {len(ordered_sources) - 23} skipped / 0 failed'
    )
    expect(page.locator('#assessment-evidence')).to_contain_text('Partial')
    expect(page.locator('#assessment-evidence')).to_contain_text('9 retained results')
    expect(page.locator('#assessment-producers')).to_have_text(f'23 of {len(ordered_sources)} completed')
    expect(page.locator('#assessment-review')).to_contain_text(f'{len(ordered_sources) - 23} skipped')
    page.locator('#review-outcomes-button').click()
    expect(page.locator('#provider-details')).to_have_attribute('open', '')
    expect(page.locator('#provider-details summary')).to_be_focused()
    expect(page.locator('#run-count')).to_have_text('1')
    expect(page.locator('#run-list button')).to_have_count(1)
    assert page.locator('#results-title').evaluate(
        "node => Boolean(node.compareDocumentPosition(document.querySelector('#provider-title')) & Node.DOCUMENT_POSITION_FOLLOWING)"
    )
    assert page.locator('#results-title').evaluate(
        "node => Boolean(node.compareDocumentPosition(document.querySelector('#lifecycle-title')) & Node.DOCUMENT_POSITION_FOLLOWING)"
    )
    assert page.locator('#results-title').evaluate(
        "node => Boolean(node.compareDocumentPosition(document.querySelector('#run-facts')) & Node.DOCUMENT_POSITION_FOLLOWING)"
    )

    missing_credentials_row = page.locator('#provider-body tr').filter(has_text=ordered_sources[23]['name'])
    expect(missing_credentials_row.locator('td').last).to_have_text(
        'Required credentials were not configured; add them, then retry.'
    )
    unexpected_skip_reason = page.locator('#provider-body tr').filter(has_text=ordered_sources[24]['name']).locator('td').last
    expect(unexpected_skip_reason).to_contain_text('Credentials required:')
    expect(unexpected_skip_reason).to_contain_text('Source did not start')

    page.locator('#history-search').fill('not-present')
    expect(page.locator('#history-empty')).to_be_visible()
    page.locator('#history-search').fill('')
    page.get_by_role('button', name='IP addresses 2').click()
    expect(page.locator('#route-count')).to_have_text('2')
    value_column = page.locator('.tabulator-col[tabulator-field="value"]')
    value_filter = value_column.locator('.tabulator-header-filter input')
    dns_filter = page.locator('.tabulator-col[tabulator-field="dns_status"] .tabulator-header-filter input')
    expect(value_filter).to_have_attribute('placeholder', 'Filter values')
    expect(dns_filter).to_have_attribute('placeholder', 'Filter DNS')

    value_filter.press_sequentially('198.51')
    expect(page.locator('.tabulator-row:visible')).to_have_count(1)
    expect(page.locator('.tabulator-row:visible')).to_contain_text('198.51.100.10')
    value_filter.press('ControlOrMeta+a')
    value_filter.press('Backspace')
    expect(page.locator('.tabulator-row:visible')).to_have_count(2)
    dns_filter.press_sequentially('not captured')
    expect(page.locator('.tabulator-row:visible')).to_have_count(2)
    dns_filter.press('ControlOrMeta+a')
    dns_filter.press('Backspace')
    expect(page.locator('.tabulator-row:visible')).to_have_count(2)

    resize_handles = page.locator('.tabulator-header .tabulator-col-resize-handle')
    expect(resize_handles).to_have_count(2)
    selection_column_width = page.locator('.tabulator-header .tabulator-row-header').bounding_box()['width']
    assert 40 <= selection_column_width <= 56
    resize_handle = resize_handles.first
    initial_width = value_column.bounding_box()['width']
    handle_box = resize_handle.bounding_box()
    page.mouse.move(handle_box['x'] + handle_box['width'] / 2, handle_box['y'] + handle_box['height'] / 2)
    page.mouse.down()
    page.mouse.move(handle_box['x'] + handle_box['width'] / 2 + 80, handle_box['y'] + handle_box['height'] / 2)
    page.mouse.up()
    assert value_column.bounding_box()['width'] >= initial_width + 60

    page.locator('.tabulator-row').first.click()
    expect(page.locator('#copy-route-button')).to_have_text('Copy selected (1)')
    page.locator('#copy-route-button').click()
    expect(page.locator('#toast')).to_have_text('Copied 1 selected IP addresses.')
    assert page.evaluate('navigator.clipboard.readText()') == '192.0.2.10'

    with page.expect_download() as jsonl_download:
        page.get_by_role('button', name='All JSONL').click()
    exported_records = [json.loads(line) for line in Path(jsonl_download.value.path()).read_text(encoding='utf-8').splitlines()]
    assert exported_records[0]['type'] == 'summary'
    assert exported_records[0]['evidence_status'] == 'partial'
    assert any(record['type'] == 'ip' and record['value'] == '192.0.2.10' for record in exported_records[1:])

    page.get_by_role('button', name='Start enumeration').first.click()
    expect(page.locator('#new-run-dialog').get_by_text('Credentials required:', exact=False).first).to_be_visible()
    page.get_by_role('button', name='Select all P0').click()
    assert page.locator('[data-activity="P0"] input:checked').count() == len(
        [source for source in passive_sources if source['ready']]
    )
    assert page.locator('[data-activity="P1"] input:checked, [data-activity="P2"] input:checked').count() == 0
    assert page.locator('.action-grid input:checked').count() == 0
    page.get_by_role('button', name='Clear', exact=True).click()
    assert page.locator('[data-activity="P0"] input:checked').count() == 0
    expect(page.locator('#activity-summary')).to_have_text('P0 off · P1 off · P2 off')

    page.keyboard.press('Escape')
    expect(page.get_by_role('button', name='Start enumeration').first).to_be_focused()
    page.get_by_role('button', name='Hostnames 1').click()
    page.set_viewport_size({'width': 390, 'height': 844})
    expect(page.locator('#provider-outcome-summary')).to_be_visible()
    expect(page.get_by_role('columnheader', name='Outcome')).to_be_visible()
    expect(page.get_by_role('columnheader', name='Results')).to_be_hidden()
    expect(page.locator('.tabulator-col[tabulator-field="value"]')).to_be_visible()
    assert page.locator('.tabulator-col[tabulator-field="value"]').bounding_box()['width'] >= 250
    expect(page.locator('#route-overflow-cue')).to_be_visible()
    value_filter.scroll_into_view_if_needed()
    expect(value_filter).to_be_visible()
    assert value_filter.bounding_box()['height'] >= 44
    assert page.locator('#route-tabs').evaluate('node => node.scrollWidth > node.clientWidth')
