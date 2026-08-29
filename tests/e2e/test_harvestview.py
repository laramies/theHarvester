from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.harvestview_e2e


def test_schedule_page_creates_and_manages_two_target_passive_schedule(
    harvestview_server_url: str,
    page: Page,
) -> None:
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto(f'{harvestview_server_url}/schedules')

    expect(page.get_by_role('heading', name='Create a schedule')).to_be_visible()
    expect(page.locator('#runtime-health')).to_have_text('Preview mode · execution disabled')
    expect(page.locator('#source-readiness')).to_contain_text('passive sources are ready')
    expect(page.locator('.source-option.is-unready').first).to_contain_text('Credentials required:')

    theme_button = page.locator('#theme-button')
    for theme in ('light', 'dark', 'system'):
        theme_button.click()
        expect(page.locator('html')).to_have_attribute('data-theme', theme)
    assert page.evaluate("localStorage.getItem('runs-theme')") == 'system'

    page.locator('#schedule-name').focus()
    page.keyboard.press('Tab')
    expect(page.locator('#schedule-targets')).to_be_focused()
    page.locator('#schedule-name').fill('Blog inventory')
    page.locator('#schedule-targets').fill('Example.Test.\nexample.test')
    expect(page.locator('#target-summary')).to_have_text('1 unique target')
    page.locator('#schedule-targets').fill('example.test\nexample.org')
    expect(page.locator('#target-summary')).to_have_text('2 unique targets')
    page.locator('#schedule-frequency').select_option('monthly')
    page.locator('#schedule-start').fill('2030-01-31T09:00')
    page.locator('#schedule-timezone').fill('America/New_York')
    expect(page.locator('#monthly-help')).to_be_visible()
    expect(page.locator('#monthly-help')).to_contain_text('final day')
    crtsh = page.locator('.source-option').filter(has_text='crtsh')
    expect(crtsh.locator('input')).to_be_enabled()
    crtsh.locator('input').check()

    page.locator('#create-schedule-button').click()

    card = page.locator('.schedule-card').filter(has_text='Blog inventory')
    expect(card).to_be_visible()
    expect(card).to_contain_text('example.test, example.org')
    expect(card).to_contain_text('2')
    expect(card).to_contain_text('Monthly')
    card.get_by_text('Upcoming occurrences').click()
    expect(card.locator('.upcoming-occurrences')).to_contain_text('Feb 28, 2030')
    expect(card.get_by_role('button', name='Pause')).to_be_visible()
    schedules = page.evaluate("fetch('/api/v1/schedules').then((response) => response.json())")
    assert schedules[0]['run']['dns_resolve'] is False
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')

    card.get_by_role('button', name='Edit').click()
    expect(page.get_by_role('heading', name='Edit schedule')).to_be_visible()
    expect(page.locator('#schedule-name')).to_have_value('Blog inventory')
    expect(page.locator('#schedule-frequency')).to_have_value('monthly')
    page.get_by_role('button', name='Cancel edit').click()
    expect(page.locator('#schedule-name')).to_be_focused()
    expect(page.get_by_role('heading', name='Create a schedule')).to_be_visible()
    card.get_by_role('button', name='Edit').click()
    card.get_by_role('button', name='Pause').click()
    card = page.locator('.schedule-card').filter(has_text='Blog inventory')
    expect(card.get_by_role('button', name='Resume')).to_be_visible()
    page.locator('#schedule-name').fill('Blog inventory every week')
    page.locator('#schedule-frequency').select_option('daily')
    expect(page.locator('#monthly-help')).to_be_hidden()
    page.locator('#schedule-interval').fill('7')
    page.get_by_role('button', name='Save changes').click()

    card = page.locator('.schedule-card').filter(has_text='Blog inventory every week')
    expect(card).to_be_visible()
    expect(card).to_contain_text('Every 7 days')
    expect(card.get_by_role('button', name='Resume')).to_be_visible()
    expect(page.get_by_role('heading', name='Create a schedule')).to_be_visible()
    expect(page.get_by_role('button', name='Cancel edit')).to_be_hidden()
    updated = page.evaluate("fetch('/api/v1/schedules').then((response) => response.json())")
    assert updated[0]['timing']['frequency'] == 'daily'
    assert updated[0]['timing']['interval'] == 7
    card.get_by_role('button', name='Resume').click()
    card = page.locator('.schedule-card').filter(has_text='Blog inventory every week')
    expect(card.get_by_role('button', name='Pause')).to_be_visible()

    card.get_by_role('button', name='Pause').click()
    card = page.locator('.schedule-card').filter(has_text='Blog inventory')
    expect(card.get_by_role('button', name='Resume')).to_be_visible()
    card.get_by_role('button', name='Resume').click()
    card = page.locator('.schedule-card').filter(has_text='Blog inventory')
    expect(card.get_by_role('button', name='Pause')).to_be_visible()

    page.route(
        '**/api/v1/schedules/*/run-now',
        lambda route: route.fulfill(
            status=202,
            json={
                'schedule_id': 'browser-test',
                'scheduled_for': '2026-08-20T12:00:00+00:00',
                'run_ids': ['one', 'two'],
                'skipped_targets': [],
                'errors': [],
            },
        ),
    )
    page.once('dialog', lambda dialog: dialog.accept())
    card.get_by_role('button', name='Run now').click()
    expect(page.locator('#toast')).to_have_text('Queued 2 run(s); skipped 0.')

    page.route(
        '**/api/v1/schedules/*/dispatches?limit=1000',
        lambda route: route.fulfill(
            json=[
                {
                    'schedule_id': 'browser-test',
                    'scheduled_for': '2026-08-20T12:00:00+00:00',
                    'target': target,
                    'run_id': f'run-{index}',
                    'state': 'queued',
                    'error': None,
                }
                for index, target in enumerate(('example.test', 'example.org', 'example.net'), start=1)
            ]
        ),
    )
    history_button = card.get_by_role('button', name='History')
    history_button.focus()
    history_button.press('Enter')
    expect(page.get_by_role('dialog')).to_be_visible()
    expect(page.locator('#close-dispatch-dialog')).to_be_focused()
    expect(page.locator('#dispatch-grid.tabulator')).to_be_visible()
    expect(page.locator('#dispatch-grid')).to_contain_text('example.test')
    expect(page.locator('#dispatch-grid')).to_contain_text('example.org')
    expect(page.locator('#dispatch-grid')).to_contain_text('example.net')
    page.keyboard.press('Escape')
    expect(page.get_by_role('dialog')).to_be_hidden()
    expect(history_button).to_be_focused()

    page.once('dialog', lambda dialog: dialog.accept())
    card.get_by_role('button', name='Delete').click()
    expect(page.locator('#schedule-empty')).to_be_visible()


def test_schedule_page_rejects_a_non_loopback_host_in_browser(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    browser_failures.allow_console_error('Failed to load resource: the server responded with a status of 403 (Forbidden)')
    remote_url = harvestview_server_url.replace('127.0.0.1', 'attacker.example') + '/schedules'

    def forward_non_loopback_host(route: Route) -> None:
        rejected = page.context.request.get(
            f'{harvestview_server_url}/schedules',
            headers={'Host': 'attacker.example'},
        )
        route.fulfill(status=rejected.status, headers=rejected.headers, body=rejected.body())

    page.route(remote_url, forward_non_loopback_host)
    response = page.goto(remote_url)

    assert response is not None
    assert response.status == 403
    expect(page.locator('body')).to_contain_text('theHarvester is available only on localhost')


def test_schedule_clone_requires_fresh_authorization_for_active_work(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'active-template',
        'target': 'source.example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-19T12:00:00+00:00',
        'started_at': '2026-08-19T12:00:00+00:00',
        'completed_at': '2026-08-19T12:01:00+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 0,
        'activities': ['P1'],
        'sources': [],
        'request': {
            'target': 'source.example.test',
            'sources': [],
            'start': 25,
            'dns_recursive_depth': 1,
        },
        'source_executions': [],
        'action_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
    }
    page.route(
        f'{harvestview_server_url}/api/v1/runs?limit=500',
        lambda route: route.fulfill(json=[run]),
    )
    page.route(
        f'{harvestview_server_url}/api/v1/runs/active-template',
        lambda route: route.fulfill(json=run),
    )
    page.goto(f'{harvestview_server_url}/schedules')

    page.get_by_text('Clone all settings from an existing run', exact=True).click()
    page.locator('#template-run').select_option('active-template')
    expect(page.locator('#authorization-row')).to_be_visible()
    page.locator('#schedule-name').fill('Active clone')
    page.locator('#schedule-targets').fill('example.test')
    page.locator('#create-schedule-button').click()
    expect(page.locator('#form-error')).to_have_text(
        'Could not create schedule: Confirm authorization for the cloned DNS or direct-interaction activity. '
        'Review the schedule values and try again.'
    )
    page.locator('#authorization-confirmation').check()
    page.locator('#create-schedule-button').click()
    expect(page.locator('.schedule-card').filter(has_text='Active clone')).to_be_visible()
    schedules = page.evaluate("fetch('/api/v1/schedules').then((response) => response.json())")
    active_clone = next(schedule for schedule in schedules if schedule['name'] == 'Active clone')
    assert active_clone['run']['start'] == 25
    assert active_clone['run']['dns_recursive_depth'] == 1

    card = page.locator('.schedule-card').filter(has_text='Active clone')
    card.get_by_role('button', name='Edit').click()
    expect(page.locator('#authorization-row')).to_be_visible()
    expect(page.locator('#authorization-confirmation')).not_to_be_checked()
    page.locator('#schedule-name').fill('Updated active clone')
    page.get_by_role('button', name='Save changes').click()
    expect(page.locator('#form-error')).to_have_text(
        'Could not save schedule: Confirm authorization for the selected DNS or direct-interaction activity. '
        'Review the schedule values and try again.'
    )
    page.locator('#authorization-confirmation').check()
    page.get_by_role('button', name='Save changes').click()
    expect(page.locator('.schedule-card').filter(has_text='Updated active clone')).to_be_visible()
    updated_schedules = page.evaluate("fetch('/api/v1/schedules').then((response) => response.json())")
    updated_clone = next(schedule for schedule in updated_schedules if schedule['name'] == 'Updated active clone')
    assert updated_clone['run']['start'] == 25
    assert updated_clone['run']['dns_recursive_depth'] == 1


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
    page.locator('#submit-run-button').scroll_into_view_if_needed()
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
    expect(page.locator('#source-selection-summary')).to_have_text('Selected 1 ready source: crtsh.')
    expect(page.locator('#final-authorization-summary')).to_contain_text('Target not set')
    expect(page.locator('#final-authorization-summary')).to_contain_text('1 source: crtsh')
    page.locator('#run-target').fill('example.com')
    page.locator('[name="screenshot"]').check()
    expect(page.locator('#final-authorization-summary')).to_contain_text('Target example.com')
    expect(page.locator('#final-authorization-summary')).to_contain_text('P2 selected')
    p0_group.locator('summary').click()
    crtsh.locator('input').uncheck()
    expect(page.locator('#source-selection-summary')).to_have_text('Selected 0 ready sources.')


def test_imported_run_separates_original_execution_from_local_import(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'imported-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'imported',
        'created_at': '2026-08-16T05:37:52+00:00',
        'started_at': '2026-08-15T03:10:00+00:00',
        'completed_at': '2026-08-15T03:10:08+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'filename': 'evidence.jsonl'},
        'source_executions': [],
        'action_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/imported-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    facts = page.locator('#run-facts')
    expect(facts).to_contain_text('OriginImported evidence')
    expect(facts).to_contain_text('Imported')
    expect(facts).to_contain_text('Original started')
    expect(facts).to_contain_text('Original completed')
    expect(facts).not_to_contain_text('Submitted')
    expect(page.locator('#lifecycle-track strong')).to_have_text(['Original started', 'Original completed', 'Imported'])
    expect(page.locator('#lifecycle-note')).to_contain_text('original execution timing')


def test_hostname_tracking_filters_persisted_run_changes(
    harvestview_server_url: str,
    page: Page,
) -> None:
    changes = [
        {
            'change': 'new',
            'hostname': 'new.example.test',
            'previous_sources': [],
            'current_sources': ['beta'],
            'source_exclusive': True,
            'previous_resolution_evidence': 'not-checked',
            'current_resolution_evidence': 'positive',
            'previous_addressability': None,
            'current_addressability': 'currently-addressable',
            'blocking_sources': [],
        },
        {
            'change': 'missing',
            'hostname': 'missing.example.test',
            'previous_sources': ['alpha', 'beta'],
            'current_sources': [],
            'source_exclusive': False,
            'previous_resolution_evidence': 'positive',
            'current_resolution_evidence': 'not-checked',
            'previous_addressability': 'currently-addressable',
            'current_addressability': None,
            'blocking_sources': [],
        },
        {
            'change': 'inconclusive',
            'hostname': 'uncertain.example.test',
            'previous_sources': ['beta'],
            'current_sources': [],
            'source_exclusive': True,
            'previous_resolution_evidence': 'not-retained',
            'current_resolution_evidence': 'not-checked',
            'previous_addressability': None,
            'current_addressability': None,
            'blocking_sources': [
                {'source': 'beta', 'status': 'partial', 'error_type': 'TimeoutError', 'stop_reason': 'timeout'}
            ],
        },
        {
            'change': 'persisting',
            'hostname': 'stable.example.test',
            'previous_sources': ['alpha'],
            'current_sources': ['alpha'],
            'source_exclusive': True,
            'previous_resolution_evidence': 'positive',
            'current_resolution_evidence': 'positive',
            'previous_addressability': 'currently-addressable',
            'current_addressability': 'currently-addressable',
            'blocking_sources': [],
        },
    ]
    run = {
        'run_id': 'tracking-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-20T12:00:00+00:00',
        'started_at': '2026-08-20T12:00:00+00:00',
        'completed_at': '2026-08-20T12:01:00+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 0,
        'activities': ['P0'],
        'sources': ['alpha', 'beta'],
        'request': {'target': 'example.test', 'sources': ['alpha', 'beta']},
        'source_executions': [],
        'action_executions': [],
        'results': [],
        'screenshots': [],
        'log': '',
        'error': None,
        'hostname_tracking': {
            'target': 'example.test',
            'comparison_count': 1,
            'comparisons': [
                {
                    'run_id': 'tracking-run',
                    'completed_at': '2026-08-20T12:01:00+00:00',
                    'baseline_run_id': 'baseline-run',
                    'baseline_completed_at': '2026-08-19T12:01:00+00:00',
                    'source_cohort': ['alpha', 'beta'],
                    'counts': {'new': 1, 'persisting': 1, 'missing': 1, 'inconclusive': 1},
                }
            ],
            'hostname_changes': changes,
        },
    }
    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/tracking-run', lambda route: route.fulfill(json=run))

    page.goto(f'{harvestview_server_url}/')

    panel = page.locator('#hostname-tracking-section')
    rows = page.locator('#hostname-tracking-body tr')
    expect(panel).to_be_visible()
    expect(panel).to_contain_text('INCONCLUSIVE means')
    expect(rows).to_have_count(3)
    expect(panel).to_contain_text('TimeoutError')
    expect(panel).not_to_contain_text('stable.example.test')

    page.locator('#tracking-change-filter').select_option('persisting')
    expect(page.locator('#tracking-persisting-filter')).to_be_checked()
    expect(rows).to_have_count(1)
    expect(panel).to_contain_text('stable.example.test')
    page.locator('#tracking-persisting-filter').uncheck()
    expect(page.locator('#tracking-change-filter')).to_have_value('')
    expect(rows).to_have_count(3)

    page.locator('#tracking-exclusive-filter').check()
    expect(rows).to_have_count(2)
    expect(panel).not_to_contain_text('missing.example.test')

    page.locator('#tracking-exclusive-filter').uncheck()
    page.locator('#tracking-persisting-filter').check()
    expect(rows).to_have_count(4)
    expect(panel).to_contain_text('stable.example.test')

    page.locator('#tracking-source-filter').select_option('alpha')
    expect(rows).to_have_count(2)
    expect(panel).not_to_contain_text('new.example.test')

    page.locator('#tracking-source-filter').select_option('')
    page.locator('#tracking-resolution-filter').select_option('not-retained')
    expect(rows).to_have_count(1)
    expect(panel).to_contain_text('uncertain.example.test')


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


def test_harvestview_renders_and_filters_takeover_outcomes(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'takeover-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-15T12:00:00+00:00',
        'started_at': '2026-08-15T12:00:01+00:00',
        'completed_at': '2026-08-15T12:00:05+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'complete',
        'result_count': 2,
        'activities': ['P0', 'P2'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300, 'takeover': True},
        'source_executions': [],
        'action_executions': [
            {'action': 'takeover', 'status': 'partial', 'result_count': 2, 'duration_ms': 125},
        ],
        'results': [
            {
                'type': 'takeover',
                'value': 'bucket.example.test',
                'sources': [],
                'actions': ['takeover'],
                'details': {
                    'status': 'indicator',
                    'dns': [
                        {
                            'resolver': '1.1.1.1',
                            'cname_chain': ['missing-bucket.s3.amazonaws.com'],
                            'terminal_rcode': 'NOERROR',
                            'error_type': None,
                        }
                    ],
                    'wildcard_dns': [
                        {
                            'resolver': '1.1.1.1',
                            'cname_chain': [],
                            'terminal_rcode': 'NXDOMAIN',
                            'error_type': None,
                        }
                    ],
                    'http': [
                        {
                            'scheme': 'https',
                            'status': 404,
                            'location': None,
                            'error_type': None,
                            'body_truncated': False,
                        }
                    ],
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
            },
            {
                'type': 'takeover',
                'value': 'uncertain.example.test',
                'sources': [],
                'actions': ['takeover'],
                'details': {
                    'status': 'inconclusive',
                    'dns': [
                        {
                            'resolver': '8.8.8.8',
                            'cname_chain': [],
                            'terminal_rcode': 'ERROR',
                            'error_type': 'DNSTimeoutError',
                        }
                    ],
                    'wildcard_dns': [],
                    'http': [],
                    'indicators': [],
                    'error_types': ['DNSTimeoutError'],
                },
            },
        ],
        'screenshots': [],
        'log': '',
        'error': None,
    }

    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/takeover-run', lambda route: route.fulfill(json=run))
    page.goto(f'{harvestview_server_url}/')

    page.get_by_role('button', name='Takeover outcomes 2').click()
    rows = page.locator('.tabulator-row')
    expect(rows).to_have_count(2)
    expect(rows.first).to_contain_text('bucket.example.test')
    expect(rows.first).to_contain_text('vulnerable indicator · AWS/S3 · aws-s3@takeover-rules-v1 · HTTPS')
    expect(rows.first).to_contain_text('Candidate 1.1.1.1 · CNAME missing-bucket.s3.amazonaws.com · NOERROR')
    expect(rows.first).to_contain_text('Wildcard control 1.1.1.1 · No CNAME · NXDOMAIN')
    expect(rows.first).to_contain_text('HTTPS · HTTP 404')
    expect(rows.first).not_to_contain_text('DNS: not captured')

    page.get_by_placeholder('Filter status or errors').press_sequentially('DNSTimeoutError')
    visible_rows = page.locator('.tabulator-row:visible')
    expect(visible_rows).to_have_count(1)
    expect(visible_rows.first).to_contain_text('uncertain.example.test')
    expect(visible_rows.first).to_contain_text('inconclusive')
    expect(visible_rows.first).to_contain_text('DNSTimeoutError')


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


@pytest.mark.parametrize(
    ('viewport_width', 'viewport_height'),
    [(1440, 900), (1024, 768), (820, 1180), (390, 844)],
    ids=['desktop', 'desktop-compact', 'tablet', 'mobile'],
)
def test_hostname_actions_queue_isolated_runs(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
    viewport_width: int,
    viewport_height: int,
) -> None:
    page.set_viewport_size({'width': viewport_width, 'height': viewport_height})
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
        'results': [
            {
                'type': 'hostname',
                'value': 'api.example.com',
                'observations': [{'endpoint': 'https://192.0.2.10', 'status': 200}],
            }
        ],
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
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')

    page.locator('#provider-details summary').click()
    expect(page.locator('#provider-title')).to_have_text('Execution outcomes')
    action_row = page.locator('#provider-body tr').filter(has_text='dns-brute')
    expect(action_row).to_contain_text('Action')
    expect(action_row).to_contain_text('failed')
    expect(action_row).to_contain_text('TimeoutError')

    collapsed_actions = page.locator('.tabulator-responsive-collapse').get_by_text('Actions', exact=True)
    expect(collapsed_actions).to_be_visible()
    page.get_by_role('button', name='Take screenshot of api.example.com (P2)').click()
    review = page.locator('#result-action-dialog')
    expect(review.get_by_role('heading')).to_have_text('Review screenshot interaction')
    expect(review).to_contain_text('api.example.com')
    expect(review).to_contain_text('P2 · Direct interaction')
    expect(review).to_contain_text('Creates a separate finite run')
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
    assert submissions == []
    review.get_by_role('button', name='Start screenshot run').click()
    expect(page.locator('#toast')).to_contain_text('Screenshot captured')
    page.get_by_role('button', name='DNS brute force api.example.com (P1)').click()
    expect(review.get_by_role('heading')).to_have_text('Review DNS brute force interaction')
    expect(review).to_contain_text('P1 · DNS interaction')
    expect(review).to_contain_text('192.0.2.53')
    review.get_by_role('button', name='Start DNS brute force run').click()
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
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')


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
    page.locator('#result-action-dialog').get_by_role('button', name='Start screenshot run').click()

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


def test_failed_run_with_retained_evidence_puts_assessment_before_results(
    harvestview_server_url: str,
    page: Page,
) -> None:
    run = {
        'run_id': 'failed-evidence-run',
        'target': 'example.com',
        'status': 'failed',
        'origin': 'local',
        'created_at': '2026-08-05T12:00:00+00:00',
        'started_at': '2026-08-05T12:00:01+00:00',
        'completed_at': '2026-08-05T12:00:02+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 1,
        'activities': ['P0'],
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 25, 'deadline_seconds': 300},
        'source_executions': [
            {
                'source': 'crtsh',
                'status': 'partial',
                'result_count': 1,
                'duration_ms': 1000,
                'error_type': 'TimeoutError',
                'stop_reason': 'timeout',
            }
        ],
        'results': [{'type': 'hostname', 'value': 'api.example.com', 'sources': ['crtsh']}],
        'screenshots': [],
        'log': '',
        'error': 'Provider process exited.',
    }
    page.route(f'{harvestview_server_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{harvestview_server_url}/api/v1/runs/{run["run_id"]}', lambda route: route.fulfill(json=run))

    page.goto(f'{harvestview_server_url}/')

    expect(page.locator('#assessment-evidence')).to_contain_text('Partial')
    expect(page.get_by_role('button', name='Hostnames 1')).to_be_enabled()
    assert page.locator('.run-assessment').evaluate(
        "node => Boolean(node.compareDocumentPosition(document.querySelector('#results-section')) & Node.DOCUMENT_POSITION_FOLLOWING)"
    )


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
    expect(page.locator('#lifecycle-track strong')).to_have_text(['Original started', 'Original completed', 'Imported'])
    expect(page.get_by_role('button', name='Export all JSONL')).to_be_enabled()
    with page.expect_download() as jsonl_download:
        page.get_by_role('button', name='Export all JSONL').click()
    exported_records = [json.loads(line) for line in Path(jsonl_download.value.path()).read_text(encoding='utf-8').splitlines()]
    assert len(exported_records) == 1
    assert exported_records[0]['evidence_status'] == 'complete'
    assert exported_records[0]['result_count'] == 0
    assert exported_records[0]['source_executions'][0]['status'] == 'completed'


def test_harvestview_exports_and_reimports_completed_runs_as_sqlite(
    harvestview_server,
    page: Page,
    tmp_path: Path,
) -> None:
    harvestview_server_url = harvestview_server.url
    source_run_id = '4ef278df-ce95-4120-9241-6e71dd96ad74'
    evidence_file = tmp_path / 'completed-run.jsonl'
    write_jsonl_evidence(
        evidence_file,
        {
            'run_id': source_run_id,
            'target': 'sqlite.example.test',
            'started_at': '2026-08-08T01:00:00Z',
            'completed_at': '2026-08-08T01:01:00Z',
            'status': 'complete',
            'source_executions': [{'source': 'crtsh', 'status': 'completed', 'duration_ms': 2, 'result_count': 1}],
            'action_executions': [{'action': 'vhost', 'status': 'completed', 'duration_ms': 1, 'result_count': 1}],
            'results': [
                {
                    'type': 'hostname',
                    'value': 'admin.sqlite.example.test',
                    'sources': ['crtsh'],
                    'actions': ['vhost'],
                    'observations': [
                        {
                            'endpoint': 'https://192.0.2.8:443/',
                            'http_host': 'admin.sqlite.example.test',
                            'tls_server_name': 'admin.sqlite.example.test',
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
                    ],
                }
            ],
        },
    )

    page.goto(f'{harvestview_server_url}/')
    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(evidence_file)
    page.locator('#submit-import-button').click()

    expect(page.locator('#detail-target')).to_have_text('sqlite.example.test')
    expect(page.locator('#run-count')).to_have_text('1')
    expect(page.locator('#toast')).to_have_text('Imported completed-run.jsonl without executing discovery.')
    expect(page.get_by_role('button', name='Hostnames 1')).to_be_enabled()
    imported_run_id = page.locator('#detail-run-id').inner_text()
    with page.expect_download() as database_download:
        page.get_by_role('button', name='Export database').click()
    assert database_download.value.suggested_filename == 'theharvester-completed-runs.sqlite'
    exported_database = Path(database_download.value.path())
    portable_database = tmp_path / database_download.value.suggested_filename
    portable_database.write_bytes(exported_database.read_bytes())
    assert portable_database.read_bytes().startswith(b'SQLite format 3\x00')
    with sqlite3.connect(portable_database) as connection:
        exported_run_ids = {row[0] for row in connection.execute('SELECT run_id FROM runs')}
        exported_tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert exported_run_ids == {imported_run_id}
    assert {'run_records', 'run_worker_leases'}.isdisjoint(exported_tables)

    harvestview_server.stop()
    database = Path(harvestview_server.environment['THEHARVESTER_RUN_DB'])
    for database_file in (database, Path(f'{database}-wal'), Path(f'{database}-shm')):
        database_file.unlink(missing_ok=True)
    harvestview_server.start()

    page.goto(f'{harvestview_server_url}/')
    expect(page.get_by_role('heading', name='No enumeration runs yet')).to_be_visible()
    page.get_by_role('button', name='Import result file').first.click()
    page.locator('#result-file').set_input_files(portable_database)
    page.locator('#submit-import-button').click()

    expect(page.locator('#toast')).to_have_text('Imported 1 run from theharvester-completed-runs.sqlite; 0 already present.')
    expect(page.locator('#detail-run-id')).to_have_text(imported_run_id)
    expect(page.locator('#detail-target')).to_have_text('sqlite.example.test')
    result_row = page.locator('.tabulator-row').first
    expect(result_row).to_contain_text('admin.sqlite.example.test')
    expect(result_row).to_contain_text('https://192.0.2.8:443/ · HTTP 401 · status')
    expect(result_row).to_contain_text('crtsh')
    expect(result_row).to_contain_text('vhost')


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
    assert page.locator('.run-assessment').evaluate(
        "node => Boolean(node.compareDocumentPosition(document.querySelector('#results-title')) & Node.DOCUMENT_POSITION_FOLLOWING)"
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
    ip_route = page.get_by_role('button', name='IP addresses 2')
    ip_route.click()
    expect(ip_route).to_have_attribute('tabindex', '0')
    ip_route.focus()
    ip_route.press('ArrowRight')
    asn_route = page.get_by_role('button', name='ASNs 1')
    expect(asn_route).to_have_attribute('aria-pressed', 'true')
    expect(asn_route).to_be_focused()
    asn_route.press('ArrowLeft')
    expect(ip_route).to_be_focused()
    route_buttons = page.locator('#route-tabs [data-route]')
    assert page.locator('#route-tabs [data-route][tabindex="-1"]').count() == route_buttons.count() - 1
    ip_route.press('End')
    expect(route_buttons.last).to_be_focused()
    expect(route_buttons.last).to_have_attribute('aria-pressed', 'true')
    route_buttons.last.press('Home')
    expect(route_buttons.first).to_be_focused()
    expect(route_buttons.first).to_have_attribute('aria-pressed', 'true')
    ip_route.click()
    expect(ip_route).to_have_attribute('tabindex', '0')
    expect(page.locator('#route-count')).to_have_text('2')
    value_column = page.locator('.tabulator-col[tabulator-field="value"]')
    value_filter = value_column.locator('.tabulator-header-filter input')
    dns_filter = page.locator('.tabulator-col[tabulator-field="dns_status"] .tabulator-header-filter input')
    expect(value_filter).to_have_attribute('placeholder', 'Filter values')
    expect(dns_filter).to_have_attribute('placeholder', 'Filter DNS')
    expect(value_filter).to_have_attribute('aria-label', 'Filter Value column')
    expect(dns_filter).to_have_attribute('aria-label', 'Filter DNS column')
    expect(page.get_by_role('checkbox', name='Select all rows on this route')).to_be_visible()
    expect(page.get_by_role('checkbox', name='Select 192.0.2.10')).to_be_visible()

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
    page.locator('#result-workbench').scroll_into_view_if_needed()
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
        page.get_by_role('button', name='Export all JSONL').click()
    exported_records = [json.loads(line) for line in Path(jsonl_download.value.path()).read_text(encoding='utf-8').splitlines()]
    assert exported_records[0]['type'] == 'summary'
    assert exported_records[0]['evidence_status'] == 'partial'
    assert any(record['type'] == 'ip' and record['value'] == '192.0.2.10' for record in exported_records[1:])

    page.get_by_role('button', name='Start enumeration').first.click()
    expect(page.locator('#new-run-dialog').get_by_text('Credentials required:', exact=False).first).to_be_visible()
    assert page.locator('.source-choice small').first.evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 12
    assert page.locator('.action-choice small').first.evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 12
    assert page.locator('#final-authorization-summary').evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 12
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
    page.set_viewport_size({'width': 820, 'height': 1180})
    assert page.locator('.app-shell').evaluate("node => getComputedStyle(node).display === 'block'")
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
    page.set_viewport_size({'width': 390, 'height': 844})
    assert page.locator('.version-badge').evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 11
    assert page.locator('.run-meta').first.evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 12
    assert page.locator('.source-choice small').first.evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 16
    assert page.locator('.action-choice small').first.evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 16
    assert page.locator('#final-authorization-summary').evaluate('node => parseFloat(getComputedStyle(node).fontSize)') >= 16
    row_checkbox = page.get_by_role('checkbox', name='Select hostname.example.com').bounding_box()
    header_checkbox = page.get_by_role('checkbox', name='Select all rows on this route').bounding_box()
    assert row_checkbox['width'] >= 44
    assert row_checkbox['height'] >= 44
    assert header_checkbox['width'] >= 44
    assert header_checkbox['height'] >= 44
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
    expect(page.get_by_role('button', name='Next Page')).to_be_visible()
    workbench_box = page.locator('#result-workbench').bounding_box()
    paginator_box = page.locator('.tabulator-paginator').bounding_box()
    assert paginator_box['x'] + paginator_box['width'] <= workbench_box['x'] + workbench_box['width'] + 1
