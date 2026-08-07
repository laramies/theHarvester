from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.harvestview_e2e


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


def test_harvestview_page_replaces_a_legacy_root_cookie(
    harvestview_server_url: str,
    page: Page,
) -> None:
    page.context.add_cookies(
        [
            {
                'name': 'theharvester-api-key',
                'value': 'stale-api-key',
                'url': harvestview_server_url,
            }
        ]
    )
    api_statuses = record_api_statuses(page, harvestview_server_url)
    page.goto(f'{harvestview_server_url}/')

    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()
    assert api_statuses['/api/v1/sources'] == 200
    assert api_statuses['/api/v1/runs'] == 200
    expect(page.get_by_text('Invalid API key')).to_have_count(0)
    assert {cookie['path'] for cookie in page.context.cookies() if cookie['name'] == 'theharvester-api-key'} == {'/api/v1'}


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
    page.set_default_timeout(2_000)
    page.get_by_role('button', name='Start enumeration').first.click()
    page.get_by_role('button', name='Clear', exact=True).click()
    page.locator('#run-target').fill('example.com')
    page.get_by_text('Advanced execution controls', exact=True).click()
    page.locator('#run-start').fill('25')
    page.locator('#run-deadline').fill('86400')
    page.locator('[name="proxies"]').check()
    page.locator('[name="shodan"]').check()
    page.locator('[name="dns_lookup"]').check()
    page.locator('#dns-recursive-depth').fill('3')
    page.locator('#dns-recursive-query-limit').fill('1234')
    page.locator('#dns-recursive-runtime-seconds').fill('12.5')
    page.locator('#dns-resolvers').fill('192.0.2.53, 198.51.100.53, 203.0.113.53')

    expect(page.locator('#activity-summary')).to_have_text('P0 selected · P1 selected · P2 off')
    page.locator('[data-activity="P0"] input[value="crtsh"]').check()
    page.locator('#submit-run-button').click()
    expect(page.locator('#new-run-error')).to_have_text('Controls captured')

    assert captured == {
        'target': 'example.com',
        'sources': ['crtsh'],
        'limit': 500,
        'start': 25,
        'deadline_seconds': 86_400,
        'proxies': True,
        'dns_lookup': True,
        'dns_resolve': False,
        'dns_resolvers': ['192.0.2.53', '198.51.100.53', '203.0.113.53'],
        'dns_recursive_depth': 3,
        'dns_recursive_query_limit': 1_234,
        'dns_recursive_runtime_seconds': 12.5,
        'dns_brute': False,
        'shodan': True,
        'screenshot': False,
        'take_over': False,
        'api_scan': False,
    }


def test_harvestview_can_select_sources_by_result_capability(harvestview_server_url: str, page: Page) -> None:
    page.goto(f'{harvestview_server_url}/')
    catalog = page.context.request.get(f'{harvestview_server_url}/api/v1/sources').json()
    expected = {source['name'] for source in catalog if 'ips' in source['capabilities']}

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
            'take_over': True,
        },
        'source_executions': [],
        'results': [{'type': 'subdomain', 'value': 'api.example.com'}],
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
    evidence_file = tmp_path / 'empty-run.json'
    evidence_file.write_text(
        json.dumps(
            {
                'run_id': 'harvestview-e2e-empty-run',
                'target': 'example.com',
                'started_at': '2026-08-05T12:00:00+00:00',
                'completed_at': '2026-08-05T12:00:25+00:00',
                'status': 'complete',
                'source_executions': [
                    {'source': 'CRTsh', 'status': 'empty', 'result_count': 0, 'duration_ms': 25000},
                ],
                'results': [],
            }
        ),
        encoding='utf-8',
    )

    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(evidence_file)
    page.locator('#submit-import-button').click()

    expect(page.locator('#results-empty-title')).to_have_text('Enumeration completed')
    expect(page.locator('#results-summary')).to_have_text('0 normalized results · 0 succeeded / 1 empty / 0 skipped / 0 failed.')
    expect(page.locator('#results-empty-copy')).to_have_text(
        'CRTsh returned no normalized evidence. The retained evidence record is complete.'
    )
    expect(page.locator('#lifecycle-track strong')).to_have_text(['Submitted', 'Started', 'Completed'])


def test_harvestview_can_import_and_analyze_fixture_evidence_through_the_real_ui(
    harvestview_server_url: str,
    page: Page,
    tmp_path: Path,
) -> None:
    page.set_viewport_size({'width': 1440, 'height': 900})
    page.context.grant_permissions(['clipboard-read', 'clipboard-write'], origin=harvestview_server_url)
    page.goto(f'{harvestview_server_url}/')
    catalog = page.context.request.get(f'{harvestview_server_url}/api/v1/sources').json()
    passive_sources = [source for source in catalog if source['activity'] == 'P0']
    credentialed = [source for source in passive_sources if source['credentials']]
    uncredentialed = [source for source in passive_sources if not source['credentials']]
    ordered_sources = uncredentialed[:23] + credentialed[:2] + uncredentialed[23:] + credentialed[2:]
    assert len(ordered_sources) == len(passive_sources)
    assert ordered_sources[23]['credentials']
    assert ordered_sources[24]['credentials']

    evidence = {
        'run_id': 'harvestview-e2e-broad-run',
        'target': 'example.com',
        'started_at': '2026-08-04T12:00:01+00:00',
        'completed_at': '2026-08-04T12:03:21+00:00',
        'status': 'partial',
        'source_executions': [
            {
                'source': source['name'],
                'status': 'succeeded' if index < 3 else 'empty' if index < 23 else 'skipped',
                'result_count': 1 if index < 3 else 0,
                'duration_ms': index + 1,
                **({'error_type': 'SourceDidNotStart'} if index >= 23 else {}),
                **({'stop_reason': 'missing-credentials'} if index == 23 else {}),
            }
            for index, source in enumerate(ordered_sources)
        ],
        'results': [
            {'type': result_type, 'value': f'{result_type}.example.com'}
            for result_type in ('subdomain', 'ip', 'asn', 'email', 'url', 'interesting-url', 'person', 'api-endpoint')
        ]
        + [
            {
                'type': 'ip',
                'value': 'zeta.example.com',
                'dns_status': 'resolved',
            }
        ],
    }
    evidence_file = tmp_path / 'broad-run.json'
    evidence_file.write_text(json.dumps(evidence), encoding='utf-8')

    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(evidence_file)
    page.locator('#submit-import-button').click()

    expect(page.locator('#provider-outcome-summary')).to_have_text(
        f'3 succeeded / 20 empty / {len(ordered_sources) - 23} skipped / 0 failed'
    )
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

    page.locator('.provider-details summary').click()
    expect(page.locator('#provider-body tr').nth(23).locator('td').last).to_have_text(
        'Required credentials were not configured; add them, then retry.'
    )
    unexpected_skip_reason = page.locator('#provider-body tr').nth(24).locator('td').last
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

    value_filter.press_sequentially('zeta')
    expect(page.locator('.tabulator-row:visible')).to_have_count(1)
    expect(page.locator('.tabulator-row:visible')).to_contain_text('zeta.example.com')
    value_filter.press('ControlOrMeta+a')
    value_filter.press('Backspace')
    expect(page.locator('.tabulator-row:visible')).to_have_count(2)
    dns_filter.press_sequentially('resolved')
    expect(page.locator('.tabulator-row:visible')).to_have_count(1)
    expect(page.locator('.tabulator-row:visible')).to_contain_text('zeta.example.com')
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
    assert page.evaluate('navigator.clipboard.readText()') == 'ip.example.com'

    with page.expect_download() as route_download:
        page.get_by_role('button', name='Route CSV').click()
    route_csv = Path(route_download.value.path()).read_text(encoding='utf-8')
    assert {'type': 'ip', 'value': 'ip.example.com', 'dns_status': ''} in csv.DictReader(io.StringIO(route_csv))

    with page.expect_download() as json_download:
        page.get_by_role('button', name='All JSON').click()
    exported_json = json.loads(Path(json_download.value.path()).read_text(encoding='utf-8'))
    assert {'type': 'ip', 'value': 'ip.example.com'} in exported_json['results']

    with page.expect_download() as csv_download:
        page.get_by_role('button', name='All CSV').click()
    exported_csv = Path(csv_download.value.path()).read_text(encoding='utf-8')
    assert {'type': 'ip', 'value': 'ip.example.com', 'dns_status': ''} in csv.DictReader(io.StringIO(exported_csv))

    page.get_by_role('button', name='Start enumeration').first.click()
    expect(page.locator('#new-run-dialog').get_by_text('Credentials required:', exact=False).first).to_be_visible()
    page.get_by_role('button', name='Select all P0').click()
    assert page.locator('[data-activity="P0"] input:checked').count() == len(passive_sources)
    assert page.locator('[data-activity="P1"] input:checked, [data-activity="P2"] input:checked').count() == 0
    assert page.locator('.action-grid input:checked').count() == 0
    page.get_by_role('button', name='Clear', exact=True).click()
    assert page.locator('[data-activity="P0"] input:checked').count() == 0
    expect(page.locator('#activity-summary')).to_have_text('P0 off · P1 off · P2 off')

    page.keyboard.press('Escape')
    expect(page.get_by_role('button', name='Start enumeration').first).to_be_focused()
    page.set_viewport_size({'width': 390, 'height': 844})
    expect(page.locator('#provider-outcome-summary')).to_be_visible()
    expect(page.locator('#route-overflow-cue')).to_be_visible()
    value_filter.scroll_into_view_if_needed()
    expect(value_filter).to_be_visible()
    assert value_filter.bounding_box()['height'] >= 44
    assert page.locator('#route-tabs').evaluate('node => node.scrollWidth > node.clientWidth')
